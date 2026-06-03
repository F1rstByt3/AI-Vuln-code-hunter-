"""Object-storage abstraction.

Dev uses S3/MinIO (multipart uploads survive 10GB+). Prod uses Azure Blob with
managed identity. Both expose the same async interface used by ingestion.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

import aioboto3

from app.config import settings


class ObjectStorage(ABC):
    @abstractmethod
    async def create_multipart(self, key: str) -> str: ...

    @abstractmethod
    async def upload_part(self, key: str, upload_id: str, part: int, body: bytes) -> str: ...

    @abstractmethod
    async def complete_multipart(self, key: str, upload_id: str, parts: list[dict]) -> None: ...

    @abstractmethod
    async def put_object(self, key: str, body: bytes) -> None: ...

    @abstractmethod
    async def download_to_path(self, key: str, dest: str) -> None: ...

    @abstractmethod
    async def stream(self, key: str) -> AsyncIterator[bytes]: ...


class S3Storage(ObjectStorage):
    def __init__(self) -> None:
        self._session = aioboto3.Session()
        self._bucket = settings.s3_bucket

    def _client(self):
        return self._session.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name=settings.s3_region,
        )

    async def create_multipart(self, key: str) -> str:
        async with self._client() as s3:
            resp = await s3.create_multipart_upload(Bucket=self._bucket, Key=key)
            return resp["UploadId"]

    async def upload_part(self, key: str, upload_id: str, part: int, body: bytes) -> str:
        async with self._client() as s3:
            resp = await s3.upload_part(
                Bucket=self._bucket, Key=key, UploadId=upload_id, PartNumber=part, Body=body
            )
            return resp["ETag"]

    async def complete_multipart(self, key: str, upload_id: str, parts: list[dict]) -> None:
        mp = {"Parts": [{"PartNumber": p["part"], "ETag": p["etag"]} for p in sorted(
            parts, key=lambda x: x["part"])]}
        async with self._client() as s3:
            await s3.complete_multipart_upload(
                Bucket=self._bucket, Key=key, UploadId=upload_id, MultipartUpload=mp
            )

    async def put_object(self, key: str, body: bytes) -> None:
        async with self._client() as s3:
            await s3.put_object(Bucket=self._bucket, Key=key, Body=body)

    async def download_to_path(self, key: str, dest: str) -> None:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        async with self._client() as s3:
            await s3.download_file(self._bucket, key, dest)

    async def stream(self, key: str) -> AsyncIterator[bytes]:
        async with self._client() as s3:
            resp = await s3.get_object(Bucket=self._bucket, Key=key)
            async for chunk in resp["Body"]:
                yield chunk


class AzureBlobStorage(ObjectStorage):
    """Prod backend. Block-blob staging maps cleanly onto S3 multipart semantics."""

    def __init__(self) -> None:
        from azure.storage.blob.aio import BlobServiceClient

        if settings.azure_storage_connection_string:
            self._svc = BlobServiceClient.from_connection_string(
                settings.azure_storage_connection_string
            )
        else:
            from azure.identity.aio import DefaultAzureCredential

            url = f"https://{settings.azure_storage_account}.blob.core.windows.net"
            self._svc = BlobServiceClient(url, credential=DefaultAzureCredential())
        self._container = settings.azure_storage_container

    def _blob(self, key: str):
        return self._svc.get_blob_client(container=self._container, blob=key)

    async def create_multipart(self, key: str) -> str:
        return key  # Azure stages blocks by id; no server-side upload id needed.

    async def upload_part(self, key: str, upload_id: str, part: int, body: bytes) -> str:
        block_id = f"{part:08d}".encode().hex()
        await self._blob(key).stage_block(block_id, body)
        return block_id

    async def complete_multipart(self, key: str, upload_id: str, parts: list[dict]) -> None:
        from azure.storage.blob import BlobBlock

        blocks = [BlobBlock(block_id=p["etag"]) for p in sorted(parts, key=lambda x: x["part"])]
        await self._blob(key).commit_block_list(blocks)

    async def put_object(self, key: str, body: bytes) -> None:
        await self._blob(key).upload_blob(body, overwrite=True)

    async def download_to_path(self, key: str, dest: str) -> None:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        stream = await self._blob(key).download_blob()
        with open(dest, "wb") as fh:
            async for chunk in stream.chunks():
                fh.write(chunk)

    async def stream(self, key: str) -> AsyncIterator[bytes]:
        stream = await self._blob(key).download_blob()
        async for chunk in stream.chunks():
            yield chunk


def get_storage() -> ObjectStorage:
    if settings.storage_backend == "azure_blob":
        return AzureBlobStorage()
    return S3Storage()
