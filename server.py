
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.tools import FunctionTool
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from starlette.responses import JSONResponse

RUNTIME_PLACEHOLDER_RE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$")


def _runtime_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value is None:
            continue
        cleaned = value.strip()
        if not cleaned or RUNTIME_PLACEHOLDER_RE.fullmatch(cleaned):
            continue
        return cleaned
    return default


class StaticApiKeyVerifier(TokenVerifier):
    def __init__(self, api_keys: Iterable[str], base_url: str | None = None) -> None:
        super().__init__(base_url=base_url)
        self._api_keys = [key for key in api_keys if key]

    async def verify_token(self, token: str) -> AccessToken | None:
        for key in self._api_keys:
            if secrets.compare_digest(token, key):
                return AccessToken(token=token, client_id="google-workspace-fast-mcp", scopes=[])
        return None


def _repo_root() -> Path:
    return Path(__file__).resolve().parent


def _load_manifest() -> list[dict[str, Any]]:
    path = _repo_root() / "tool_manifest_google.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing tool manifest: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    tools = data.get("tools")
    if not isinstance(tools, list):
        raise RuntimeError("tool_manifest_google.json is invalid")
    return tools


def _load_api_keys() -> list[str]:
    keys: list[str] = []
    for key in (_runtime_env("GOOGLE_WORKSPACE_MCP_API_KEY"), _runtime_env("MCP_API_KEY")):
        if key and key.strip():
            keys.append(key.strip())
    multi = _runtime_env("MCP_API_KEYS")
    if multi:
        keys.extend([x.strip() for x in multi.split(",") if x.strip()])
    return list(dict.fromkeys(keys))


def _derive_key(master_key: str) -> bytes:
    if re.fullmatch(r"[0-9a-fA-F]{64}", master_key or ""):
        return bytes.fromhex(master_key)
    return hashlib.sha256(master_key.encode("utf-8")).digest()


def _decrypt_legacy(master_key: str, encoded: str) -> dict[str, Any]:
    iv_hex, tag_hex, cipher_hex = str(encoded or "").split(":", 2)
    iv = bytes.fromhex(iv_hex)
    tag = bytes.fromhex(tag_hex)
    ciphertext = bytes.fromhex(cipher_hex)
    plaintext = AESGCM(_derive_key(master_key)).decrypt(iv, ciphertext + tag, None)
    return json.loads(plaintext.decode("utf-8"))


def _parse_expiry(payload: dict[str, Any]) -> datetime | None:
    value = payload.get("expiry_date")
    if isinstance(value, (int, float)):
        if value > 10_000_000_000:
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        return datetime.fromtimestamp(value, tz=timezone.utc)
    value = payload.get("expiry")
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _as_scopes(value: Any) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        value = value.strip()
        return value.split() if value else None
    return None


class CredentialStore:
    def __init__(self) -> None:
        custom_dir = _runtime_env("GOOGLE_MCP_CREDENTIALS_DIR")
        self._base_dir = Path(custom_dir).expanduser() if custom_dir else Path.home() / ".google_workspace_mcp" / "credentials"
        self._base_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, email: str) -> Path:
        return self._base_dir / f"{email}.json"

    def get(self, email: str) -> Credentials | None:
        user = str(email or "").strip().lower()
        if not user:
            return None
        path = self._path(user)
        if not path.exists():
            return None
        raw = path.read_text(encoding="utf-8").strip()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            master_key = _runtime_env("MASTER_KEY")
            if not master_key:
                return None
            try:
                payload = _decrypt_legacy(master_key, raw)
            except Exception:
                return None

        client_id = payload.get("oauth_client_id") or _runtime_env("GOOGLE_OAUTH_CLIENT_ID")
        client_secret = payload.get("oauth_client_secret") or _runtime_env("GOOGLE_OAUTH_CLIENT_SECRET")
        token = payload.get("token") or payload.get("access_token")
        refresh_token = payload.get("refresh_token")
        token_uri = payload.get("token_uri") or "https://oauth2.googleapis.com/token"
        scopes = _as_scopes(payload.get("scopes") or payload.get("scope"))
        if not client_id or not client_secret or (not token and not refresh_token):
            return None

        creds = Credentials(
            token=token,
            refresh_token=refresh_token,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
        )
        expiry = _parse_expiry(payload)
        if expiry is not None:
            creds.expiry = expiry
        if not creds.valid and creds.refresh_token:
            try:
                creds.refresh(GoogleAuthRequest())
            except Exception:
                return None
        return creds


def _decode_b64url(value: str | None) -> str:
    if not value:
        return ""
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="replace")

def _extract_headers(headers: list[dict[str, Any]] | None, wanted: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    lookup = {w.lower(): w for w in wanted}
    for header in headers or []:
        name = str(header.get("name") or "")
        value = str(header.get("value") or "")
        key = lookup.get(name.lower())
        if key:
            found[key] = value
    return found


def _extract_bodies(payload: dict[str, Any]) -> tuple[str, str]:
    text_parts: list[str] = []
    html_parts: list[str] = []

    def walk(part: dict[str, Any]) -> None:
        mime_type = str(part.get("mimeType") or "")
        decoded = _decode_b64url((part.get("body") or {}).get("data"))
        if mime_type == "text/plain" and decoded:
            text_parts.append(decoded)
        elif mime_type == "text/html" and decoded:
            html_parts.append(decoded)
        for child in part.get("parts") or []:
            if isinstance(child, dict):
                walk(child)

    walk(payload)
    return ("\n".join(text_parts).strip(), "\n".join(html_parts).strip())


def _extract_doc_text(content: list[dict[str, Any]] | None) -> str:
    out: list[str] = []
    for element in content or []:
        paragraph = element.get("paragraph")
        if paragraph:
            for run in paragraph.get("elements") or []:
                text = ((run.get("textRun") or {}).get("content"))
                if text:
                    out.append(str(text))
        table = element.get("table")
        if table:
            for row in table.get("tableRows") or []:
                cells: list[str] = []
                for cell in row.get("tableCells") or []:
                    cells.append(_extract_doc_text(cell.get("content")))
                out.append("\t".join(cells))
    return "".join(out).strip()


def _extract_slide_text(slide: dict[str, Any]) -> str:
    lines: list[str] = []
    for element in slide.get("pageElements") or []:
        text_block = ((element.get("shape") or {}).get("text") or {})
        chunk: list[str] = []
        for te in text_block.get("textElements") or []:
            value = ((te.get("textRun") or {}).get("content"))
            if value:
                chunk.append(str(value))
        if chunk:
            lines.append("".join(chunk).strip())
    return "\n".join([line for line in lines if line])


class GoogleRuntime:
    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    def _svc(self, user_email: str, api: str, version: str):
        creds = self._store.get(user_email)
        if creds is None:
            raise PermissionError(f"Authorization required for {user_email}")
        return build(api, version, credentials=creds, cache_discovery=False)

    def _resolve_drive_item(self, drive, file_id: str) -> tuple[str, dict[str, Any]]:
        current = file_id
        for _ in range(6):
            meta = drive.files().get(
                fileId=current,
                fields="id,mimeType,shortcutDetails(targetId,targetMimeType),name,webViewLink",
                supportsAllDrives=True,
            ).execute()
            if meta.get("mimeType") != "application/vnd.google-apps.shortcut":
                return current, meta
            target = ((meta.get("shortcutDetails") or {}).get("targetId"))
            if not target:
                break
            current = target
        raise RuntimeError(f"Unable to resolve drive item: {file_id}")

    def _resolve_folder(self, drive, folder_id: str) -> str:
        resolved, meta = self._resolve_drive_item(drive, folder_id)
        if meta.get("mimeType") != "application/vnd.google-apps.folder":
            raise RuntimeError(f"Resolved id '{resolved}' is not a folder")
        return resolved

    async def dispatch(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "list_users":
            svc = self._svc(args["user_google_email"], "admin", "directory_v1")
            params = {"customer": "my_customer", "maxResults": args.get("page_size", 100)}
            if args.get("domain"):
                params["domain"] = args["domain"]
            if args.get("query"):
                params["query"] = args["query"]
            if args.get("page_token"):
                params["pageToken"] = args["page_token"]
            data = svc.users().list(**params).execute()
            return {"users": data.get("users", []), "nextPageToken": data.get("nextPageToken")}
        if name == "get_user":
            svc = self._svc(args["user_google_email"], "admin", "directory_v1")
            return {"user": svc.users().get(userKey=args["user_key"]).execute()}
        if name == "create_user":
            svc = self._svc(args["user_google_email"], "admin", "directory_v1")
            data = svc.users().insert(
                body={
                    "primaryEmail": args["primary_email"],
                    "name": {"givenName": args["given_name"], "familyName": args["family_name"]},
                    "password": args["password"],
                    "orgUnitPath": args.get("org_unit_path", "/"),
                    "changePasswordAtNextLogin": args.get("change_password_next_login", True),
                }
            ).execute()
            return {"created": True, "user": data}
        if name == "list_groups":
            svc = self._svc(args["user_google_email"], "admin", "directory_v1")
            params = {"customer": "my_customer", "maxResults": args.get("page_size", 100)}
            if args.get("domain"):
                params["domain"] = args["domain"]
            if args.get("user_key"):
                params["userKey"] = args["user_key"]
            if args.get("page_token"):
                params["pageToken"] = args["page_token"]
            data = svc.groups().list(**params).execute()
            return {"groups": data.get("groups", []), "nextPageToken": data.get("nextPageToken")}
        if name == "list_admin_activities":
            svc = self._svc(args["user_google_email"], "admin", "reports_v1")
            params: dict[str, Any] = {
                "userKey": args.get("user_key", "all"),
                "applicationName": args["application_name"],
                "maxResults": args.get("page_size", 100),
            }
            for key, param in (("start_time", "startTime"), ("end_time", "endTime"), ("event_name", "eventName"), ("page_token", "pageToken")):
                if args.get(key):
                    params[param] = args[key]
            data = svc.activities().list(**params).execute()
            return {"activities": data.get("items", []), "nextPageToken": data.get("nextPageToken")}

        if name == "list_calendars":
            svc = self._svc(args["user_google_email"], "calendar", "v3")
            data = svc.calendarList().list(maxResults=args.get("page_size", 100), pageToken=args.get("page_token")).execute()
            return {"calendars": data.get("items", []), "nextPageToken": data.get("nextPageToken")}
        if name == "get_events":
            svc = self._svc(args["user_google_email"], "calendar", "v3")
            calendar_id = args.get("calendar_id", "primary")
            if args.get("event_id"):
                return {"event": svc.events().get(calendarId=calendar_id, eventId=args["event_id"]).execute()}
            params: dict[str, Any] = {
                "calendarId": calendar_id,
                "maxResults": args.get("page_size", 25),
                "singleEvents": True,
                "orderBy": "startTime",
                "pageToken": args.get("page_token"),
                "q": args.get("query"),
                "timeMin": args.get("time_min") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            if args.get("time_max"):
                params["timeMax"] = args["time_max"]
            data = svc.events().list(**params).execute()
            return {"events": data.get("items", []), "nextPageToken": data.get("nextPageToken")}
        if name == "create_event":
            svc = self._svc(args["user_google_email"], "calendar", "v3")
            body: dict[str, Any] = {
                "summary": args["summary"],
                "start": {"dateTime": args["start_time"]} if "T" in args["start_time"] else {"date": args["start_time"]},
                "end": {"dateTime": args["end_time"]} if "T" in args["end_time"] else {"date": args["end_time"]},
            }
            if args.get("description") is not None:
                body["description"] = args["description"]
            if args.get("location") is not None:
                body["location"] = args["location"]
            if args.get("attendees"):
                body["attendees"] = [{"email": x} if isinstance(x, str) else x for x in args["attendees"]]
            if args.get("add_google_meet"):
                body["conferenceData"] = {"createRequest": {"requestId": secrets.token_hex(8), "conferenceSolutionKey": {"type": "hangoutsMeet"}}}
            data = svc.events().insert(calendarId=args.get("calendar_id", "primary"), body=body, conferenceDataVersion=1 if args.get("add_google_meet") else 0).execute()
            return {"created": True, "event": data}
        if name == "delete_event":
            svc = self._svc(args["user_google_email"], "calendar", "v3")
            svc.events().delete(calendarId=args.get("calendar_id", "primary"), eventId=args["event_id"]).execute()
            return {"deleted": True, "eventId": args["event_id"]}

        if name == "list_spaces":
            svc = self._svc(args["user_google_email"], "chat", "v1")
            flt = ""
            if args.get("space_type") == "room":
                flt = 'spaceType = "SPACE"'
            elif args.get("space_type") == "dm":
                flt = 'spaceType = "DIRECT_MESSAGE"'
            return {"spaces": svc.spaces().list(pageSize=args.get("page_size", 100), filter=flt).execute().get("spaces", [])}
        if name == "create_space":
            svc = self._svc(args["user_google_email"], "chat", "v1")
            data = svc.spaces().create(body={"displayName": args["display_name"], "spaceType": args.get("space_type", "SPACE"), "externalUserAllowed": args.get("external_user_allowed", False)}).execute()
            return {"created": True, "space": data}
        if name == "list_members":
            svc = self._svc(args["user_google_email"], "chat", "v1")
            data = svc.spaces().members().list(parent=args["space_id"], pageSize=args.get("page_size", 100)).execute()
            return {"memberships": data.get("memberships", [])}
        if name == "add_member":
            svc = self._svc(args["user_google_email"], "chat", "v1")
            data = svc.spaces().members().create(parent=args["space_id"], body={"member": {"name": args["member_name"]}}).execute()
            return {"created": True, "membership": data}
        if name == "remove_member":
            svc = self._svc(args["user_google_email"], "chat", "v1")
            svc.spaces().members().delete(name=args["member_name"]).execute()
            return {"deleted": True, "memberName": args["member_name"]}
        if name == "get_messages":
            svc = self._svc(args["user_google_email"], "chat", "v1")
            data = svc.spaces().messages().list(parent=args["space_id"], pageSize=args.get("page_size", 50), orderBy="createTime desc").execute()
            return {"messages": data.get("messages", [])}
        if name == "send_message":
            svc = self._svc(args["user_google_email"], "chat", "v1")
            params: dict[str, Any] = {"parent": args["space_id"], "body": {"text": args["message_text"]}}
            if args.get("thread_key"):
                params["threadKey"] = args["thread_key"]
            return {"sent": True, "message": svc.spaces().messages().create(**params).execute()}

        if name == "create_doc":
            svc = self._svc(args["user_google_email"], "docs", "v1")
            data = svc.documents().create(body={"title": args["title"]}).execute()
            if args.get("content") and data.get("documentId"):
                svc.documents().batchUpdate(documentId=data["documentId"], body={"requests": [{"insertText": {"location": {"index": 1}, "text": args["content"]}}]}).execute()
            return {"created": True, "document": data}
        if name == "get_doc_content":
            svc = self._svc(args["user_google_email"], "docs", "v1")
            data = svc.documents().get(documentId=args["document_id"]).execute()
            return {"document": data, "text": _extract_doc_text((data.get("body") or {}).get("content"))}
        if name == "modify_doc_text":
            svc = self._svc(args["user_google_email"], "docs", "v1")
            reqs: list[dict[str, Any]] = []
            if args.get("start_index") is not None and args.get("end_index") is not None:
                reqs.append({"deleteContentRange": {"range": {"startIndex": int(args["start_index"]), "endIndex": int(args["end_index"])}}})
                reqs.append({"insertText": {"location": {"index": int(args["start_index"] )}, "text": args["text"]}})
            else:
                reqs.append({"insertText": {"location": {"index": int(args.get("index", 1))}, "text": args["text"]}})
            data = svc.documents().batchUpdate(documentId=args["document_id"], body={"requests": reqs}).execute()
            return {"updated": True, "result": data}
        if name in {"search_drive_files", "list_drive_items", "get_drive_file_content", "create_drive_file", "get_drive_file_permissions"}:
            svc = self._svc(args["user_google_email"], "drive", "v3")
            if name == "search_drive_files":
                query = str(args["query"])
                if "=" not in query and "contains" not in query:
                    escaped = query.replace("'", "\\'")
                    query = f"fullText contains '{escaped}'"
                params: dict[str, Any] = {
                    "q": query,
                    "pageSize": args.get("page_size", 10),
                    "pageToken": args.get("page_token"),
                    "fields": "nextPageToken, files(id,name,mimeType,webViewLink,iconLink,modifiedTime,size)",
                    "supportsAllDrives": True,
                    "includeItemsFromAllDrives": args.get("include_items_from_all_drives", True),
                }
                if args.get("drive_id"):
                    params["driveId"] = args["drive_id"]
                    params["corpora"] = args.get("corpora", "drive")
                elif args.get("corpora"):
                    params["corpora"] = args["corpora"]
                data = svc.files().list(**params).execute()
                return {"files": data.get("files", []), "nextPageToken": data.get("nextPageToken")}
            if name == "list_drive_items":
                folder_id = self._resolve_folder(svc, args.get("folder_id", "root"))
                params: dict[str, Any] = {
                    "q": f"'{folder_id}' in parents and trashed=false",
                    "pageSize": args.get("page_size", 100),
                    "pageToken": args.get("page_token"),
                    "fields": "nextPageToken, files(id,name,mimeType,webViewLink,iconLink,modifiedTime,size)",
                    "supportsAllDrives": True,
                    "includeItemsFromAllDrives": args.get("include_items_from_all_drives", True),
                }
                if args.get("drive_id"):
                    params["driveId"] = args["drive_id"]
                    params["corpora"] = args.get("corpora", "drive")
                elif args.get("corpora"):
                    params["corpora"] = args["corpora"]
                data = svc.files().list(**params).execute()
                return {"files": data.get("files", []), "nextPageToken": data.get("nextPageToken")}
            if name == "get_drive_file_content":
                file_id, meta = self._resolve_drive_item(svc, args["file_id"])
                mime_type = meta.get("mimeType")
                if mime_type == "application/vnd.google-apps.document":
                    raw = svc.files().export(fileId=file_id, mimeType="text/plain").execute()
                    content = raw.decode("utf-8", errors="replace")
                elif mime_type == "application/vnd.google-apps.spreadsheet":
                    raw = svc.files().export(fileId=file_id, mimeType="text/csv").execute()
                    content = raw.decode("utf-8", errors="replace")
                else:
                    raw = svc.files().get(fileId=file_id, alt="media").execute()
                    content = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                return {"file": meta, "resolvedId": file_id, "content": content}
            if name == "create_drive_file":
                if not args.get("content"):
                    raise ValueError("content is required")
                folder_id = self._resolve_folder(svc, args.get("folder_id", "root"))
                data = svc.files().create(body={"name": args["file_name"], "parents": [folder_id], "mimeType": args.get("mime_type", "text/plain")}, media_body=args["content"], fields="id,name,webViewLink,mimeType", supportsAllDrives=True).execute()
                return {"created": True, "file": data}
            if name == "get_drive_file_permissions":
                file_id, _ = self._resolve_drive_item(svc, args["file_id"])
                data = svc.files().get(fileId=file_id, fields="id,name,mimeType,size,modifiedTime,permissions(id,type,role,emailAddress,domain,expirationTime),webViewLink,shared", supportsAllDrives=True).execute()
                return {"file": data}

        if name in {"search_gmail_messages", "get_gmail_message_content", "get_gmail_messages_content_batch", "get_gmail_attachment_content"}:
            svc = self._svc(args["user_google_email"], "gmail", "v1")
            if name == "search_gmail_messages":
                data = svc.users().messages().list(userId="me", q=args["query"], maxResults=args.get("page_size", 10), pageToken=args.get("page_token")).execute()
                return {"messages": data.get("messages", []), "nextPageToken": data.get("nextPageToken")}
            if name == "get_gmail_message_content":
                msg = svc.users().messages().get(userId="me", id=args["message_id"], format="full").execute()
                payload = msg.get("payload") or {}
                text_body, html_body = _extract_bodies(payload)
                return {"message": msg, "headers": _extract_headers(payload.get("headers"), ["Subject", "From", "To", "Cc", "Message-ID", "Date"]), "body": text_body or html_body, "textBody": text_body, "htmlBody": html_body}
            if name == "get_gmail_messages_content_batch":
                fmt = args.get("format", "full")
                out: list[dict[str, Any]] = []
                for message_id in (args.get("message_ids") or [])[:25]:
                    try:
                        msg = svc.users().messages().get(userId="me", id=message_id, format="metadata" if fmt == "metadata" else "full", metadataHeaders=["Subject", "From", "To", "Cc", "Message-ID", "Date"]).execute()
                        payload = msg.get("payload") or {}
                        item: dict[str, Any] = {"messageId": message_id, "headers": _extract_headers(payload.get("headers"), ["Subject", "From", "Date"]), "message": msg}
                        if fmt != "metadata":
                            text_body, html_body = _extract_bodies(payload)
                            item["body"] = text_body or html_body
                        out.append(item)
                    except Exception as exc:
                        out.append({"messageId": message_id, "error": str(exc)})
                return {"results": out}
            if name == "get_gmail_attachment_content":
                data = svc.users().messages().attachments().get(userId="me", messageId=args["message_id"], id=args["attachment_id"]).execute()
                return {"attachment": data}

        if name in {"list_spreadsheets", "get_spreadsheet_info", "read_sheet_values", "modify_sheet_values"}:
            if name == "list_spreadsheets":
                svc = self._svc(args["user_google_email"], "drive", "v3")
                data = svc.files().list(q="mimeType='application/vnd.google-apps.spreadsheet' and trashed=false", pageSize=args.get("page_size", 25), pageToken=args.get("page_token"), fields="nextPageToken, files(id,name,modifiedTime,webViewLink)", orderBy="modifiedTime desc", supportsAllDrives=True, includeItemsFromAllDrives=True).execute()
                return {"spreadsheets": data.get("files", []), "nextPageToken": data.get("nextPageToken")}
            svc = self._svc(args["user_google_email"], "sheets", "v4")
            if name == "get_spreadsheet_info":
                data = svc.spreadsheets().get(spreadsheetId=args["spreadsheet_id"], fields="spreadsheetId,properties(title,locale),sheets(properties(title,sheetId,gridProperties(rowCount,columnCount)))").execute()
                return {"spreadsheet": data}
            if name == "read_sheet_values":
                data = svc.spreadsheets().values().get(spreadsheetId=args["spreadsheet_id"], range=args.get("range_name", "A1:Z1000")).execute()
                return {"range": data.get("range"), "values": data.get("values", [])}
            if name == "modify_sheet_values":
                if args.get("clear_values"):
                    data = svc.spreadsheets().values().clear(spreadsheetId=args["spreadsheet_id"], range=args["range_name"], body={}).execute()
                    return {"cleared": True, "result": data}
                values = args.get("values")
                if isinstance(values, str):
                    values = json.loads(values)
                if not isinstance(values, list):
                    raise ValueError("values must be a 2D array")
                data = svc.spreadsheets().values().update(spreadsheetId=args["spreadsheet_id"], range=args["range_name"], valueInputOption=args.get("value_input_option", "USER_ENTERED"), body={"values": values}).execute()
                return {"updated": True, "result": data}

        if name in {"create_presentation", "get_presentation", "create_slide", "add_textbox"}:
            svc = self._svc(args["user_google_email"], "slides", "v1")
            if name == "create_presentation":
                data = svc.presentations().create(body={"title": args.get("title", "Untitled Presentation")}).execute()
                return {"created": True, "presentation": data}
            if name == "get_presentation":
                data = svc.presentations().get(presentationId=args["presentation_id"]).execute()
                return {"presentation": data, "slides": [{"slideId": s.get("objectId"), "text": _extract_slide_text(s)} for s in data.get("slides", [])]}
            if name == "create_slide":
                req: dict[str, Any] = {"createSlide": {"slideLayoutReference": {"predefinedLayout": args.get("layout", "TITLE_AND_BODY")}}}
                if args.get("insertion_index") is not None:
                    req["createSlide"]["insertionIndex"] = int(args["insertion_index"])
                data = svc.presentations().batchUpdate(presentationId=args["presentation_id"], body={"requests": [req]}).execute()
                return {"created": True, "result": data}
            if name == "add_textbox":
                object_id = f"textbox_{secrets.token_hex(4)}"
                reqs = [{"createShape": {"objectId": object_id, "shapeType": "TEXT_BOX", "elementProperties": {"pageObjectId": args["page_id"], "size": {"width": {"magnitude": float(args["width"]), "unit": "PT"}, "height": {"magnitude": float(args["height"]), "unit": "PT"}}, "transform": {"scaleX": 1, "scaleY": 1, "translateX": float(args["x"]), "translateY": float(args["y"]), "unit": "PT"}}}}, {"insertText": {"objectId": object_id, "text": args["text"]}}]
                data = svc.presentations().batchUpdate(presentationId=args["presentation_id"], body={"requests": reqs}).execute()
                return {"created": True, "elementId": object_id, "result": data}

        if name in {"list_task_lists", "create_task_list", "delete_task_list", "list_tasks", "create_task", "update_task", "delete_task", "complete_task", "clear_completed_tasks"}:
            svc = self._svc(args["user_google_email"], "tasks", "v1")
            if name == "list_task_lists":
                data = svc.tasklists().list(maxResults=args.get("max_results", 100), pageToken=args.get("page_token")).execute()
                return {"taskLists": data.get("items", []), "nextPageToken": data.get("nextPageToken")}
            if name == "create_task_list":
                return {"created": True, "taskList": svc.tasklists().insert(body={"title": args["title"]}).execute()}
            if name == "delete_task_list":
                svc.tasklists().delete(tasklist=args["task_list_id"]).execute()
                return {"deleted": True, "taskListId": args["task_list_id"]}
            if name == "list_tasks":
                data = svc.tasks().list(tasklist=args["task_list_id"], maxResults=args.get("max_results", 20), pageToken=args.get("page_token"), showCompleted=args.get("show_completed", True), showDeleted=args.get("show_deleted", False), showHidden=args.get("show_hidden", False)).execute()
                return {"tasks": data.get("items", []), "nextPageToken": data.get("nextPageToken")}
            if name == "create_task":
                body: dict[str, Any] = {"title": args["title"]}
                if args.get("notes") is not None:
                    body["notes"] = args["notes"]
                if args.get("due") is not None:
                    body["due"] = args["due"]
                params: dict[str, Any] = {"tasklist": args["task_list_id"], "body": body}
                if args.get("parent"):
                    params["parent"] = args["parent"]
                return {"created": True, "task": svc.tasks().insert(**params).execute()}
            if name == "update_task":
                body = {}
                for key in ("title", "notes", "status", "due"):
                    if args.get(key) is not None:
                        body[key] = args[key]
                return {"updated": True, "task": svc.tasks().patch(tasklist=args["task_list_id"], task=args["task_id"], body=body).execute()}
            if name == "delete_task":
                svc.tasks().delete(tasklist=args["task_list_id"], task=args["task_id"]).execute()
                return {"deleted": True, "taskId": args["task_id"]}
            if name == "complete_task":
                data = svc.tasks().patch(tasklist=args["task_list_id"], task=args["task_id"], body={"status": "completed"}).execute()
                return {"completed": True, "task": data}
            if name == "clear_completed_tasks":
                svc.tasks().clear(tasklist=args["task_list_id"]).execute()
                return {"cleared": True, "taskListId": args["task_list_id"]}

        raise NotImplementedError(f"Tool '{name}' is not implemented")


def _register_tools(server: FastMCP, runtime: GoogleRuntime, manifest: list[dict[str, Any]]) -> None:
    for spec in manifest:
        name = str(spec.get("name") or "").strip()
        if not name:
            continue
        params = spec.get("parameters") or {"type": "object", "properties": {}, "additionalProperties": True}
        desc = str(spec.get("description") or "")

        async def _fn(_name: str = name, **kwargs: Any) -> dict[str, Any]:
            try:
                return await runtime.dispatch(_name, kwargs)
            except Exception as exc:
                return {"isError": True, "error": str(exc)}

        server.add_tool(
            FunctionTool(
                name=name,
                description=desc,
                parameters=params,
                output_schema={"type": "object", "additionalProperties": True},
                fn=_fn,
            )
        )


manifest = _load_manifest()
runtime = GoogleRuntime(CredentialStore())

api_keys = _load_api_keys()
auth = StaticApiKeyVerifier(api_keys=api_keys, base_url=_runtime_env("BASE_URL")) if api_keys else None
server = FastMCP("google-workspace-fast-mcp", auth=auth)
mcp = server
_register_tools(server, runtime, manifest)


@server.custom_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def root_health(_request):
    return JSONResponse({"status": "ok", "server": "google-workspace-fast-mcp"})


@server.custom_route("/health", methods=["GET", "HEAD"], include_in_schema=False)
async def health(_request):
    return JSONResponse({"status": "ok", "server": "google-workspace-fast-mcp"})


@server.custom_route("/healthz", methods=["GET", "HEAD"], include_in_schema=False)
async def healthz(_request):
    return JSONResponse({"status": "ok", "server": "google-workspace-fast-mcp"})


def main() -> None:
    transport_name = _runtime_env("FASTMCP_TRANSPORT", default="streamable-http").lower()
    if transport_name == "stdio":
        server.run()
    else:
        host = _runtime_env("HOST", default="0.0.0.0")
        port = int(_runtime_env("PORT", default="8000"))
        server.run(transport=transport_name, host=host, port=port)


if __name__ == "__main__":
    main()
