import logging
from typing import Any

from graft.core.loader import DATASET_IDENTIFIER_PATTERN, MAX_RULE_IDENTIFIER_LEN
from graft.core.models.dataset import DatasetEnvelope, DatasetMetadata
from graft.core.ports.dataset import DatasetPort
from graft.engines.secops.client import SecOpsApiError, SecOpsClient

logger = logging.getLogger("graft.secops.datasets")

_MAX_DATASET_ROWS = 1000
_DEFAULT_PULLED_REFERENCE = (
    "https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/"
    "projects.locations.instances.dataTables"
)


def _extract_table_name(raw_name: str) -> str:
    if "/dataTables/" in raw_name:
        return raw_name.rsplit("/dataTables/", 1)[-1].strip()
    return raw_name.strip()


def _is_compatible_single_string_column(column_info: object) -> bool:
    if not isinstance(column_info, list) or len(column_info) != 1:
        return False
    col = column_info[0]
    if not isinstance(col, dict):
        return False
    orig_col = str(col.get("originalColumn", ""))
    col_type = str(col.get("columnType", "STRING")).upper()
    return orig_col == "value" and col_type in (
        "STRING",
        "DATA_TABLE_COLUMN_TYPE_UNSPECIFIED",
        "",
    )


class SecOpsDatasetAdapter(DatasetPort):
    def __init__(self, client: SecOpsClient) -> None:
        self._client = client

    def _fetch_rows(self, table_name: str) -> tuple[str, ...]:
        values: list[str] = []
        page_token: str | None = None
        while True:
            params: dict[str, str] = {"pageSize": str(_MAX_DATASET_ROWS)}
            if page_token:
                params["pageToken"] = page_token
            resp = self._client.request(
                "GET",
                f"dataTables/{table_name}/dataTableRows",
                params=params,
                api_version="v1",
            )
            raw_rows = resp.get("dataTableRows", [])
            if isinstance(raw_rows, list):
                for item in raw_rows:
                    if isinstance(item, dict):
                        row_vals = item.get("values", [])
                        if isinstance(row_vals, list) and row_vals:
                            val_str = str(row_vals[0])
                            if val_str:
                                values.append(val_str)
            next_tok = resp.get("nextPageToken")
            if isinstance(next_tok, str) and next_tok.strip():
                page_token = next_tok.strip()
                if len(values) > _MAX_DATASET_ROWS:
                    break
            else:
                break
        return tuple(values)

    def _build_envelope_from_table_obj(
        self,
        table_obj: dict[str, Any],
        strict_compatibility: bool,
    ) -> DatasetEnvelope | None:
        raw_name_val = table_obj.get("name")
        if not isinstance(raw_name_val, str) or not raw_name_val.strip():
            return None
        table_name = _extract_table_name(raw_name_val)
        if not table_name:
            return None

        col_info = table_obj.get("columnInfo", [])
        if not _is_compatible_single_string_column(col_info):
            if strict_compatibility:
                raise RuntimeError(
                    f"Remote SecOps Data Table '{table_name}' has an incompatible schema "
                    f"(expected 1 STRING column named 'value', got {col_info}). "
                    "Rename the Graft dataset or migrate the remote table."
                )
            logger.debug(
                "Skipping incompatible SecOps Data Table '%s' during discovery", table_name
            )
            return None

        if not (
            1 <= len(table_name) <= MAX_RULE_IDENTIFIER_LEN
            and DATASET_IDENTIFIER_PATTERN.match(table_name)
            and table_name != "index"
        ):
            logger.debug("Skipping Data Table '%s' with non-conforming identifier", table_name)
            return None

        rows = self._fetch_rows(table_name)
        if not strict_compatibility and (not rows or len(rows) > _MAX_DATASET_ROWS):
            logger.debug(
                "Skipping Data Table '%s' with %d rows (must be 1..%d)",
                table_name,
                len(rows),
                _MAX_DATASET_ROWS,
            )
            return None

        raw_desc = str(table_obj.get("description", "")).strip()
        desc = raw_desc[:128] if raw_desc else f"Imported SecOps Data Table {table_name}"[:128]

        return DatasetEnvelope(
            metadata=DatasetMetadata(
                name=table_name,
                description=desc,
                owners=("Security Operations",),
                tags=("secops", "dataset"),
                references=(_DEFAULT_PULLED_REFERENCE,),
            ),
            values=rows,
        )

    def list_datasets(
        self,
        names: tuple[str, ...] | None = None,
    ) -> tuple[DatasetEnvelope, ...]:
        results: list[DatasetEnvelope] = []
        if names is not None:
            for name in names:
                logger.debug("Fetching SecOps Data Table '%s'", name)
                try:
                    resp = self._client.request(
                        "GET",
                        f"dataTables/{name}",
                        api_version="v1",
                    )
                except SecOpsApiError as exc:
                    if exc.status_code == 404:
                        logger.debug("SecOps Data Table '%s' does not exist on tenant (404)", name)
                        continue
                    raise
                envelope = self._build_envelope_from_table_obj(resp, strict_compatibility=True)
                if envelope is not None:
                    results.append(envelope)
            return tuple(results)

        page_token: str | None = None
        while True:
            params: dict[str, str] = {"pageSize": "1000"}
            if page_token:
                params["pageToken"] = page_token
            resp = self._client.request(
                "GET",
                "dataTables",
                params=params,
                api_version="v1",
            )
            tables_raw = resp.get("dataTables", [])
            if isinstance(tables_raw, list):
                for item in tables_raw:
                    if isinstance(item, dict):
                        env = self._build_envelope_from_table_obj(
                            item,
                            strict_compatibility=False,
                        )
                        if env is not None:
                            results.append(env)
            next_tok = resp.get("nextPageToken")
            if isinstance(next_tok, str) and next_tok.strip():
                page_token = next_tok.strip()
            else:
                break
        return tuple(results)

    def _bulk_replace_rows(self, name: str, values: tuple[str, ...]) -> None:
        requests_payload = [{"dataTableRow": {"values": [val]}} for val in values]
        self._client.request(
            "POST",
            f"dataTables/{name}/dataTableRows:bulkReplace",
            body={"requests": requests_payload},
            api_version="v1",
        )

    def create_dataset(self, dataset: DatasetEnvelope) -> str:
        name = dataset.metadata.name
        logger.debug("Creating SecOps Data Table '%s' header", name)
        self._client.request(
            "POST",
            "dataTables",
            params={"dataTableId": name},
            body={
                "description": dataset.metadata.description,
                "columnInfo": [
                    {
                        "columnIndex": 0,
                        "originalColumn": "value",
                        "columnType": "STRING",
                    }
                ],
            },
            api_version="v1",
        )
        try:
            logger.debug(
                "Populating %d rows in SecOps Data Table '%s' via bulkReplace",
                len(dataset.values),
                name,
            )
            self._bulk_replace_rows(name, dataset.values)
        except Exception as exc:
            logger.warning(
                "Two-stage partial mutation: Data Table '%s' header was created, "
                "but dataTableRows:bulkReplace failed: %s",
                name,
                exc,
            )
            raise
        return name

    def update_dataset(self, dataset: DatasetEnvelope) -> None:
        name = dataset.metadata.name
        logger.debug("Updating SecOps Data Table '%s' description", name)
        self._client.request(
            "PATCH",
            f"dataTables/{name}",
            params={"updateMask": "description"},
            body={"description": dataset.metadata.description},
            api_version="v1",
        )
        try:
            logger.debug(
                "Replacing %d rows in SecOps Data Table '%s' via bulkReplace",
                len(dataset.values),
                name,
            )
            self._bulk_replace_rows(name, dataset.values)
        except Exception as exc:
            logger.warning(
                "Two-stage partial mutation: Data Table '%s' description was updated, "
                "but dataTableRows:bulkReplace failed: %s",
                name,
                exc,
            )
            raise
