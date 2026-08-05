import ctypes
from getpass import getpass

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

try:
    from fido2.client.windows import WindowsClient

    use_winclient = (
        WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin()
    )
except Exception:
    use_winclient = False

# Ignore this if block. I use a custom IPC service at https://github.com/AdityaMitra5102/python-fido2/tree/namedpipe to easily access CTAP directly without Admin right
# More about this at https://github.com/Yubico/python-fido2/pull/293
# To use this path, install python-fido2 from the above repo. Follow the instructions at https://github.com/AdityaMitra5102/python-fido2/tree/namedpipe#installation to install the service.
# However if the IPC is not used and on Windows, you need to start this flaskapp as admin
if use_winclient:
    try:
        from fido2.hid import ipc_available
        if ipc_available():
            use_winclient = False
    except:
        print("Using WindowsClient.")
        # I should have killed the program here
        # because WindowsClient does not support PreviewSign Extension as of today
        # but I am not doing it out of optimism
        # hoping Microsoft will add the support for this extension soon
        # and this code path will magically start working.


class CliInteraction(UserInteraction):
    def __init__(self):
        self._pin = None

    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        if not self._pin:
            self._pin = getpass("Enter PIN: ")
        return self._pin

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev


def get_client(predicate=None, **kwargs):
    client_data_collector = DefaultClientDataCollector("https://example.com")

    if use_winclient:
        return WindowsClient(client_data_collector), None

    user_interaction = kwargs.pop("user_interaction", None) or CliInteraction()

    for dev in enumerate_devices():
        client = Fido2Client(
            dev,
            client_data_collector=client_data_collector,
            user_interaction=user_interaction,
            **kwargs,
        )
        if predicate is None or predicate(client.info):
            return client, client.info
    else:
        raise ValueError("No suitable Authenticator found!")

# The above code is copied from Yubico/python-fido2/examples/exampleclient.py


from flask import *
from fido2 import cbor
from fido2.cose import ESP256_SPLIT_ARKG_PLACEHOLDER, CoseKey
from fido2.ctap2.extensions import PreviewSignExtension
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
import datetime
import os
from dataclasses import dataclass
from typing import Any
import pickle
import base64
import io

uv = "discouraged"

productname = "YubiSign"

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}

app = Flask(__name__)



@dataclass
class Arguments:
    key_handle: Any
    args: Any
    credentials: Any
    pub_key: Any

    def serialize(self):
        return base64.urlsafe_b64encode(pickle.dumps(self)).decode()

    @staticmethod
    def deserialize(data):
        args = pickle.loads(base64.urlsafe_b64decode(data.encode()))
        return args


class YubikeySigner(ec.EllipticCurvePrivateKey):
    def __init__(self, public_key: ec.EllipticCurvePublicKey):
        self._public_key = public_key

    def public_key(self):
        return self._public_key

    @property
    def key_size(self):
        return self._public_key.key_size

    def set_args(self, args):
        self.args = args

    def sign(
        self, data: bytes, signature_algorithm: ec.EllipticCurveSignatureAlgorithm
    ):
        client, info = get_client(
            lambda info: PreviewSignExtension.NAME in info.extensions,
            extensions=[PreviewSignExtension()],
        )

        request_options, state = server.authenticate_begin(
            self.args.credentials, user_verification=uv
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        ph_data = digest.finalize()
        result = client.get_assertion(
            {
                **request_options["publicKey"],
                "extensions": {
                    PreviewSignExtension.NAME: {
                        "signByCredential": {
                            websafe_encode(self.args.credentials[0].credential_id): {
                                "keyHandle": self.args.key_handle,
                                "tbs": ph_data,
                                "additionalArgs": cbor.encode(self.args.args),
                            },
                        },
                    }
                },
            }
        )
        result = result.get_response(0)

        sign_result = result.client_extension_results[PreviewSignExtension.NAME]
        signature = websafe_decode(sign_result.get("signature"))
        server.authenticate_complete(state, self.args.credentials, result)
        return signature

    def exchange(self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey):
        raise NotImplementedError()

    @property
    def curve(self):
        return self._public_key.curve

    def private_numbers(self):
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()

    def __copy__(self):
        raise NotImplementedError()

    def __deepcopy__(self, memo: dict[Any, Any]):
        raise NotImplementedError()


from cryptography.hazmat.primitives.asymmetric import ec
from endesive.pdf import cms


def sign_pdf(pdf_bytes, private_key, cert_pem) -> bytes:

    cert = x509.load_pem_x509_certificate(cert_pem)

    org_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
    org_name = org_attrs[0].value if org_attrs else None

    date = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S+00'00'")
    dct = {
        "sigflags": 3,
        "sigpage": 0,
        "sigbutton": True,
        "signature": f"Signed by {org_name} with {productname}" if org_name else f"Signed with {productname}",
        "signaturebox": (0, 0, 100, 100),
        "aligned": 4096,
        "signingdate": date.encode(),
    }

    othercerts = []

    datas = cms.sign(
        pdf_bytes,
        dct,
        private_key,
        cert,
        othercerts,
        "sha256",
    )

    return pdf_bytes + datas


@app.route("/")
def index():
    args = request.cookies.get("args", "")
    return render_template("index.html", args=args, productname=productname)


@app.route("/keygen", methods=["POST"])
def keygen():
    client, info = get_client(
        lambda info: PreviewSignExtension.NAME in info.extensions,
        extensions=[PreviewSignExtension()],
    )
    create_options, state = server.register_begin(
        user,
        resident_key_requirement="discouraged",
        user_verification=uv,
        authenticator_attachment="cross-platform",
    )

    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {
                PreviewSignExtension.NAME: {
                    "generateKey": {"algorithms": [ESP256_SPLIT_ARKG_PLACEHOLDER]}
                }
            },
        }
    )

    auth_data = server.register_complete(state, result)
    credentials = [auth_data.credential_data]
    sign_result = result.client_extension_results.previewSign
    sign_key = sign_result.generated_key
    pk = CoseKey.parse(
        cbor.decode(websafe_decode(sign_key["publicKey"]))
    )
    ctx = os.urandom(16)
    ikm = os.urandom(16)
    pk2, args = pk.derive_public_key(ikm, ctx)
    
    x_int = int.from_bytes(pk2[-2], byteorder="big")
    y_int = int.from_bytes(pk2[-3], byteorder="big")

    public_key = ec.EllipticCurvePublicNumbers(
        x=x_int, y=y_int, curve=ec.SECP256R1()
    ).public_key()

    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    arguments = Arguments(
        key_handle=sign_key.key_handle,
        args=args,
        credentials=credentials,
        pub_key=der_bytes,
    )
    params = request.get_json()
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, params["country"]),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, params["state"]),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, params["locality"]),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, params["org"]),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, params["cname"]),
        ]
    )

    signer = YubikeySigner(public_key)
    signer.set_args(arguments)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(params["cname"])]),
            critical=False,
        )
        .sign(private_key=signer, algorithm=hashes.SHA256())
    )

    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    pem = pem_bytes.decode()

    arguments.pub_key = pem_bytes

    serialized_args = arguments.serialize()
    resp = make_response(jsonify({"cert": pem, "args": serialized_args}))
    resp.set_cookie("args", serialized_args, max_age=365 * 24 * 3600)
    return resp


@app.route("/sign", methods=["POST"])
def sign():
    args = request.form.get("args")
    pdf_file = request.files.get("pdf")

    pdf_bytes = pdf_file.read()
    arguments = Arguments.deserialize(args)
    cert = x509.load_pem_x509_certificate(arguments.pub_key)
    yubipvt = YubikeySigner(cert.public_key())
    yubipvt.set_args(arguments)
    

    signed_pdf = sign_pdf(pdf_bytes, yubipvt, arguments.pub_key)
    
    return send_file(
        io.BytesIO(signed_pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="signed.pdf",
    )

import webbrowser
if __name__ == "__main__":
    print(f"Starting {productname}")
    port = 5000
    webbrowser.open(f'http://localhost:{port}')
    app.run("0.0.0.0", port=port, debug=False)
