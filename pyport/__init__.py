from datetime import datetime
from typing import Any, Dict, List, Optional

import validators
from jwt import InvalidTokenError, PyJWT


class InvalidX5UError(InvalidTokenError):
    """Error if the x5u entry is invalid."""


class InvalidMXIDError(InvalidTokenError):
    """Error if the mxid is not valid."""


class InvalidMXURIError(InvalidTokenError):
    """Error if the mx uri is not valid."""


class Passport(PyJWT):
    """Passport decode / encode."""

    X5U = 'x5u'
    ALGORITHM = 'ES256'

    def __init__(self, options: Optional[Dict] = None):
        """Initiate the class."""
        default_options = {'require': ['iat', 'orig', 'dest']}
        if options:
            default_options.update(options)
        super().__init__(default_options)

    def _validate_x5u(self, header: Dict):
        """Validate x5u header.

        Arguments:
            header: The header dictionary of the passport.

        Raises:
            InvalidX5UError: if the header is missing or is not a valid url

        """
        try:
            result = validators.url(header[self.X5U])
            if not result:
                raise InvalidX5UError('Missing valid x5u header') from result
        except (TypeError, ValueError, KeyError, AttributeError) as error:
            raise InvalidX5UError('Missing valid x5u header') from error

    def _validate_passport_claims(self, payload: Dict[str, Any]):
        """Validate passport claims of a passport payload.

        Arguments:
            payload: A payload dictionary to be validated

        Raises:
            InvalidMXIDError: if dest or orig is not a valid mxid
            InvalidMXURIError: if dest or orig is not a valid mxuri
            InvalidTokenError: if orig, dest is of wrong type or anything else fails

        """
        try:
            origin_uri = payload['orig']['uri']
            self._validate_mxuri(origin_uri)
            if not payload['dest']['uri']:
                raise InvalidTokenError('MXIDs dest missing')
            for dest_uri in payload['dest']['uri']:
                self._validate_mxuri(dest_uri)
        except (TypeError, KeyError, ValueError, AttributeError) as error:
            raise InvalidTokenError('MXIDs (dest/orig) not valid') from error

    @staticmethod
    def _validate_mxuri(entry: str):
        """Validate an mx uri.

        Arguments:
            entry: A Matrix-URI to validate.

        Raises:
            InvalidMXURIError

        """
        scheme, mxid = entry.split(':', 1)
        if not scheme == 'matrix':
            raise InvalidMXURIError(f'MXID has no valid uri scheme {scheme}')
        Passport._validate_mxid(mxid)

    @staticmethod
    def _validate_mxid(mxid: str):
        """Validate a matrix id.

        Arguments:
            mxid: A Matrix-ID to validate

        Raises:
            InvalidMXIDError: If the mxid is not valid

        """
        try:
            user, domain = mxid.rsplit(':', 1)
            if not user:
                raise InvalidMXIDError(f'MXID has not a valid user "{user}"')
            if not validators.domain(domain):
                raise InvalidMXIDError(f'MXID has not a valid domain "{domain}"')
        except (ValueError, AttributeError) as error:
            raise InvalidMXIDError(f'MXID is invalid {mxid}') from error

    def decode_complete(
        self,
        jwt: str,
        key: bytes = b"",
        algorithms: List[str] = None,
        options: Dict = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Decode a passport.

        Arguments:
            jwt: Passport string to decode and validate
            key: PEM format of the public key to check signature
            options: Dictionary of additional options for the decoder

        Returns:
            Decoded payload

        """
        result = super().decode_complete(jwt, key, algorithms, options, **kwargs)
        self._validate_passport_claims(result['payload'])
        self._validate_x5u(header=result['header'])
        return result

    def decode(self, jwt: str, key: Optional[bytes] = "", options: Optional[Dict] = None) -> Dict[str, Any]:
        """Decode a passport.

        Arguments:
            jwt: Passport string to decode and validate
            key: PEM format of the public key to check signature
            options: Dictionary of additional options for the decoder

        Returns:
            Decoded payload

        """
        return super().decode(jwt, key, options=options, algorithms=[self.ALGORITHM])

    def encode(self, cert_url: str, dest_mxid: str, origin_mxid: str, key: bytes,
               headers: Optional[Dict] = None, **kwargs) -> str:
        """Encode a valid passport.

        Arguments:
            cert_url: The url to the certificate to be retrieved
            dest_mxid: Destination mxid of the user to create the passport for
            origin_mxid: Mxid of the user issuing the passport
            key: PEM string of the private key to sign
            headers: Dictionary of additional passport headers to add
            **kwargs: All other keys will be added to the call of extended encode class.

        Returns:
             signed and json encoded passport as string

        """
        default_headers = {
            'typ': 'passport',
            'x5u': cert_url
        }
        self._validate_x5u(default_headers)
        self._validate_mxid(dest_mxid)
        self._validate_mxid(origin_mxid)

        if headers:
            default_headers.update(headers)
        matrix_url = 'matrix:{}'
        claims = {
            "dest": {"uri": [matrix_url.format(dest_mxid)]},
            "orig": {"uri": matrix_url.format(origin_mxid)},
            "iat": datetime.utcnow()
        }
        return super().encode(claims, key, self.ALGORITHM, default_headers, **kwargs)
