from datetime import datetime
from typing import Literal

from pydantic import Secret, Field

from middlewared.api.base import (
    BaseModel, Excluded, excluded_field, ForUpdateMetaclass, NonEmptyString,
    LocalUsername, RemoteUsername, HttpVerb,
)


__all__ = [
    "ApiKeyEntry", "ApiKeyCreateArgs", "ApiKeyCreateResult", "ApiKeyUpdateArgs", "ApiKeyUpdateResult",
    "ApiKeyDeleteArgs", "ApiKeyDeleteResult", "ApiKeyMyKeysArgs", "ApiKeyMyKeysResult",
]


class AllowListItem(BaseModel):
    method: HttpVerb
    resource: NonEmptyString


class ApiKeyEntry(BaseModel):
    id: int
    name: NonEmptyString = Field(max_length=200)
    username: LocalUsername | RemoteUsername | None
    user_identifier: int | str
    keyhash: Secret[str]
    created_at: datetime
    expires_at: datetime | None = None
    local: bool
    revoked: bool
    revoked_reason: str | None

    @classmethod
    def to_previous(cls, value):
        if value["username"] is None:
            value["username"] = ""

        value.pop("revoked_reason")

        return value


class ApiKeyEntryWithKey(ApiKeyEntry):
    key: str


class ApiKeyCreate(ApiKeyEntry):
    id: Excluded = excluded_field()
    username: LocalUsername | RemoteUsername
    user_identifier: Excluded = excluded_field()
    keyhash: Excluded = excluded_field()
    created_at: Excluded = excluded_field()
    local: Excluded = excluded_field()
    revoked: Excluded = excluded_field()
    revoked_reason: Excluded = excluded_field()


class ApiKeyCreateArgs(BaseModel):
    api_key_create: ApiKeyCreate


class ApiKeyCreateResult(BaseModel):
    result: ApiKeyEntryWithKey


class ApiKeyUpdate(ApiKeyCreate, metaclass=ForUpdateMetaclass):
    username: Excluded = excluded_field()
    reset: bool


class ApiKeyUpdateArgs(BaseModel):
    id: int
    api_key_update: ApiKeyUpdate


class ApiKeyUpdateResult(BaseModel):
    result: ApiKeyEntryWithKey | ApiKeyEntry


class ApiKeyDeleteArgs(BaseModel):
    id: int


class ApiKeyDeleteResult(BaseModel):
    result: Literal[True]


class ApiKeyMyKeysArgs(BaseModel):
    pass


class ApiKeyMyKeysResult(BaseModel):
    result: list[ApiKeyEntry]
