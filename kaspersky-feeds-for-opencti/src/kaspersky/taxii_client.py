#!/usr/bin/env python3
# © 2024 AO Kaspersky Lab. All Rights Reserved.
"""Kaspersky taxii client module."""

from datetime import datetime
from fnmatch import fnmatch
from typing import Any, List, Dict, Generator
from http import HTTPStatus

from requests.exceptions import HTTPError
from requests import Session
from taxii2client.common import _HTTPConnection
from taxii2client.v21 import ApiRoot, Collection, as_pages

from .stix_source import Stix21Source


class Taxii21Session:
    """
    Taxii 2.1 session is wrapper for requests.Session class which used
    to automatically pass timeout argument to all http request methods.
    """

    def __init__(self, impl: Session, timeout: int = None):
        """
            Initialize session object.
        :param impl: real session object which executes http requests.
        :param ssl_verify: whether to use TLS certificate validation (optional).
        :param timeout: timeout in seconds applied for all http requests (optional).
        """
        self._impl = impl
        self._timeout = timeout if timeout is not None else 0

    def get(self, url, **kwargs):
        """Wrapped http GET request."""
        return self._impl.get(url, timeout=self._timeout, **kwargs)

    def options(self, url, **kwargs):
        """Wrapped http OPTIONS request."""
        return self._impl.options(url, timeout=self._timeout, **kwargs)

    def head(self, url, **kwargs):
        """Wrapped http HEAD request."""
        return self._impl.head(url, timeout=self._timeout, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        """Wrapped http POST request."""
        return self._impl.post(
            url, timeout=self._timeout, data=data, json=json, **kwargs
        )

    def put(self, url, data=None, **kwargs):
        """Wrapped http PUT request."""
        return self._impl.put(url, timeout=self._timeout, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        """Wrapped http PATCH request."""
        return self._impl.patch(url, timeout=self._timeout, data=data, **kwargs)

    def delete(self, url, **kwargs):
        """Wrapped http DELETE request."""
        return self._impl.delete(url, timeout=self._timeout, **kwargs)


class Taxii21Connection(_HTTPConnection):
    """
    Taxii 2.1 connection is extention of _HTTPConnection class
    introduced to replace default implementation of session object
    because it has no ability to specify timeout for http requests.
    """

    def __init__(
        self, user: str, password: str, ssl_verify: bool = True, timeout: int = None
    ):
        """
            Initialize taxii connection object.
        :param user: username for authentication.
        :param password: password for authentication.
        :param ssl_verify: whether to use TLS certificate validation (optional).
        :param timeout: Timeout in seconds applied for all taxii requests (optional).
        """
        super().__init__(user, password, verify=ssl_verify, version="2.1")
        self.session = Taxii21Session(impl=self.session, timeout=timeout)


class Taxii21Logger:
    """Interface for logger object."""

    def log_info(self, message: str) -> None:
        """
            Log message with INFO log level.
        :param message: message to log.
        :return: none.
        """
        # pylint: disable-next=unnecessary-pass
        pass

    def log_error(self, message: str) -> None:
        """
            Log message with ERROR log level.
        :param message: message to log.
        :return: none.
        """
        # pylint: disable-next=unnecessary-pass
        pass


def make_feed_label(name: str) -> str:
    """Create label from TAXII collection name."""
    return name.removeprefix("TAXII_").lower()


def processed_stix_object(collection: str, stix_object: Dict) -> Dict:
    """Process stix2 object by adjusting some fields."""
    object_type = stix_object["type"]
    if object_type not in ["observable", "indicator"]:
        return stix_object

    if "labels" not in stix_object:
        stix_object["labels"] = []
    stix_object["labels"].append(make_feed_label(collection))

    if "valid_until" in stix_object:
        timestamp = stix_object["valid_until"]
        if timestamp.startswith("2100-"):
            del stix_object["valid_until"]

    return stix_object


# pylint: disable-next=too-few-public-methods
class Taxii21Client(Stix21Source):
    """
    Taxii 2.1 client provides access to Kaspersky TAXII Service
    to enumerate stix 2.1 objects maintained by Kaspersky Lab.
    """

    # pylint: disable-next=too-many-arguments
    def __init__(
        self,
        api_root: str,
        api_token: str,
        ssl_verify: bool = True,
        collections: List[str] = None,
        timeout: int = None,
        logger: Any = None,
    ):
        """
            Initialize taxii 2.1 client object.
            Note: usually list of collections should be specified as list of their uuid
            but here collection also can be specified by it's alias name and even more
            you can use whildcards like '*' and '?' to simplify filtering.
        :param api_root: api root of taxii server.
        :param api_token: api token for authorization.
        :param ssl_verify: whether to use TLS certificate validation (optional).
        :param collections: list of collections to visit (optional).
        :param timeout: timeout in seconds applied for all http requests (optional).
        :param logger: object to log messages (optional).
        """
        super().__init__()

        username = "taxii"
        request_timeout = timeout if timeout is not None else 30
        connection = Taxii21Connection(
            user=username,
            password=api_token,
            ssl_verify=ssl_verify,
            timeout=request_timeout,
        )

        self._api = ApiRoot(url=f"{api_root}", conn=connection)
        self._collections = collections
        self._logger = logger if logger is not None else Taxii21Logger()

    @staticmethod
    def _collection_matched(collection: Collection, expectaions: List[str]) -> bool:
        if expectaions is None:
            return True
        for expectaion in expectaions:
            if fnmatch(collection.id, expectaion):
                return True
            if fnmatch(collection.title, expectaion):
                return True
        return False

    def enumerate(self, added_after: datetime = None) -> Generator[Dict, None, None]:
        """
            Enumerate stix 2.1 objects available on taxii server for  specified collections.
            [implementation of Stix21Source.enumerate method]
        :param added_after: datetime filter to skip old objects (optional).
        :return: generator of the objects.
        """
        self._logger.log_info(f"Connecting to {self._api.url}...")
        self._api.refresh()

        expected_version = "application/taxii+json;version=2.1"
        if expected_version not in self._api.versions:
            raise RuntimeError(
                f"Specified API Root doesn't support version '{expected_version}'"
            )

        collections_to_handle = filter(
            lambda collection: Taxii21Client._collection_matched(
                collection=collection, expectaions=self._collections
            ),
            self._api.collections,
        )

        filters = {}
        if added_after is not None:
            filters["added_after"] = added_after

        for collection in collections_to_handle:
            try:
                if not collection.can_read:
                    self._logger.log_info(
                        f"Collection {collection.id} [{collection.title}] is not readable, skip it"
                    )
                    continue

                objects_count = 0
                self._logger.log_info(
                    f"Reading objects from collection {collection.id} [{collection.title}]..."
                )

                pages = as_pages(collection.get_objects, **filters)
                for envelop in pages:
                    objects_count += len(envelop["objects"])
                    for stix_object in envelop["objects"]:
                        yield processed_stix_object(
                            collection=collection.title, stix_object=stix_object
                        )

                self._logger.log_info(
                    f"Collection {collection.id} [{collection.title}] size: {objects_count} objects"
                )

            except HTTPError as exception:
                status_code = exception.response.status_code
                if status_code != HTTPStatus.NOT_FOUND:
                    raise exception

                # crutch for case 'there are no objects'
                self._logger.log_info(
                    f"Collection {collection.id} [{collection.title}] size: 0 objects"
                )
                continue
