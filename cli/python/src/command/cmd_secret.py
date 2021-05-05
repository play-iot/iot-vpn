import datetime
import functools

import click
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from src.utils.helper import DEFAULT_ENCODING, FileHelper, JsonHelper, TextHelper
from src.utils.opts_shared import CLI_CTX_SETTINGS, OutputOpts, out_dir_opts_factory

# FIXME: Need to study algorithm and cryptography type

ORGANIZATION = "QWEiO"
COUNTRY = "VN"
STATE = ""
CITY = "Hanoi"
COMMON_NAME = "qweio.app"


class CertAttributes(object):
    def __init__(self, valid_days: int, cert_org: str, cert_country: str, cert_state: str, cert_city: str,
                 cert_cn: str):
        self.valid_days = valid_days
        self.attrs = {NameOID.ORGANIZATION_NAME: cert_org, NameOID.COUNTRY_NAME: cert_country,
                      NameOID.STATE_OR_PROVINCE_NAME: cert_state, NameOID.LOCALITY_NAME: cert_city}
        self.common_name = cert_cn

    def create_x509_attributes(self, prefix_cn=""):
        attrs = [x509.NameAttribute(k, v) for k, v in self.attrs.items() if v]
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, prefix_cn + self.common_name))
        return x509.Name(attrs)


def cert_attributes_factory(root_cert):
    _org = ORGANIZATION if root_cert else None
    _country = COUNTRY if root_cert else None
    _state = STATE if root_cert else None
    _city = CITY if root_cert else None
    _common_name = COMMON_NAME if root_cert else ''

    def cert_attributes(func):
        @click.option("-ced", "--cert-valid-days", "valid_days", type=click.IntRange(1, 3650), default=730,
                      show_default=True, required=True, help="Certificate valid days [1 - 3650]")
        @click.option("-con", "--cert-organization", "cert_org", type=str, default=_org, show_default=root_cert,
                      required=root_cert, help="Certificate Organization")
        @click.option("-ccu", "--cert-country", "cert_country", type=str, default=_country, show_default=root_cert,
                      required=root_cert, help="Certificate Country name")
        @click.option("-csn", "--cert-state", "cert_state", type=str, default=_state, show_default=root_cert,
                      required=root_cert, help="Certificate State name")
        @click.option("-cln", "--cert-locality", "cert_city", type=str, default=_city, show_default=root_cert,
                      required=root_cert, help="Certificate Locality name")
        @click.option("-ccn", "--cert-common-name", "cert_cn", type=str, default=_common_name, show_default=root_cert,
                      required=root_cert, help="Certificate Common Name")
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            kwargs["cert_attributes"] = CertAttributes(kwargs.pop("valid_days"), kwargs.pop("cert_org"),
                                                       kwargs.pop("cert_country"), kwargs.pop("cert_state"),
                                                       kwargs.pop("cert_city"), kwargs.pop("cert_cn"))
            return func(*args, **kwargs)

        return wrapper

    return cert_attributes


@click.group(context_settings=CLI_CTX_SETTINGS)
def cli():
    """
    Secret utils
    """
    pass


@cli.command(name="gen-ssh")
@click.option("-u", "--users", type=str, multiple=True, required=True, help="List users")
@out_dir_opts_factory("ssh")
def gen_ssh(users, output_opts: OutputOpts):
    """
    Generate SSH key
    """
    output = {}
    crypto_backend = crypto_default_backend()
    for user in users:
        ssh_key = rsa.generate_private_key(backend=crypto_backend, public_exponent=65537, key_size=4096)
        private_ssh_key = __serialize_private_key(ssh_key)
        public_ssh_key = ssh_key.public_key() \
            .public_bytes(crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH) \
            .decode(DEFAULT_ENCODING)
        output[user] = {'private_ssh_key': private_ssh_key, 'public_ssh_key': public_ssh_key}
        FileHelper.write_file(output_opts.make_file(user + "_ssh"), private_ssh_key)
        FileHelper.write_file(output_opts.make_file(user + "_ssh.pub"), public_ssh_key)

    JsonHelper.dump(output_opts.to_fqn_file(".json"), output)


@cli.command(name="encrypt")
@click.option("-i", "--input", "value", type=str, required=True, help="Value")
@click.option("-a", "--algorithm", "algorithm", type=click.Choice(["md5", "sha1", "sha256"]), default="sha256",
              required=True, help="Algorithm to encrypt")
@click.option("-b64", "--base64", "enabled_base64", help="Enabled base64 encode", is_flag=True)
def encrypt_value(value, algorithm, enabled_base64=False):
    """
    Encrypt value by one of algorithm
    """
    click.echo(__do_encrypt(value, algorithm, enabled_base64))


@cli.command(name="gen-root-cert")
@cert_attributes_factory(True)
@out_dir_opts_factory("root-certs")
def gen_root_cert(output_opts: OutputOpts, cert_attributes: CertAttributes):
    """
    Generate Root Certification
    """
    crypto_backend = crypto_default_backend()
    algorithm = hashes.SHA512()
    now = datetime.datetime.utcnow()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=crypto_backend)
    subject = issuer = cert_attributes.create_x509_attributes()
    crt = x509.CertificateBuilder() \
        .subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number()).not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(days=cert_attributes.valid_days)) \
        .sign(private_key, algorithm, crypto_backend)
    root_private_key = __serialize_private_key(private_key)
    root_cert_key = crt.public_bytes(encoding=crypto_serialization.Encoding.PEM).decode(DEFAULT_ENCODING)
    output = {'private_key': root_private_key, 'cert_key': root_cert_key, 'serial_number': f'{crt.serial_number:0>40X}'}
    FileHelper.write_file(output_opts.to_fqn_file("key"), root_private_key)
    FileHelper.write_file(output_opts.to_fqn_file("crt"), root_cert_key)
    JsonHelper.dump(output_opts.to_fqn_file("json"), output)


@cli.command(name="gen-intermediate-cert")
@click.option("-px", "--prefix", type=str, default="vpn", help="Declares a prefix that combines with per intermediate")
@click.option("-ii", "--intermediate-item", "items", type=str, multiple=True, required=True,
              help="Declares list of signed certification intermediate name")
@click.option("-cck", "--cert-key", type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True,
              help="Path to root certificate key")
@click.option("-cpk", "--private-key", type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True,
              help="Path to root certificate private key")
@cert_attributes_factory(False)
@out_dir_opts_factory("signed-certs")
def gen_intermediate_cert(cert_key, private_key, prefix, items, output_opts: OutputOpts,
                          cert_attributes: CertAttributes):
    """
    Generate an Intermediate Signed certificate
    """
    outputs = {}
    ca_crt, ca_pkey = __load_key(cert_key, private_key)
    for item in items:
        outputs[item] = __gen_cert(f'{prefix}.{item}', cert_attributes, ca_crt, ca_pkey)
        FileHelper.write_file(output_opts.make_file(f"{item}.key"), outputs[item]['private_key'])
        FileHelper.write_file(output_opts.make_file(f"{item}.crt"), outputs[item]['cert_key'])
    JsonHelper.dump(output_opts.make_file(f"signed-intermediate-{output_opts.file}.json"), outputs)


@cli.command(name='gen-signed-cert')
@click.option('-ic', '--intermediate-code', type=str, required=True, help='Defines an Intermediate CA code')
@click.option('-fn', '--functionality', 'fn', type=str, default='device',
              help='A signed cert functionality that combines with intermediate cert and item')
@click.option('-cck', '--cert-key', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True,
              help='Path to intermediate certificate key')
@click.option('-cpk', '--private-key', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True,
              help='Path to intermediate certificate private key')
@click.option('-ii', '--item', 'items', type=str, multiple=True, help='List of signed certification name')
@click.option('--seq', default=False, flag_value=True,
              help='Enable sequence mode. Signed certification name will be in format: <prefix><digit>{length}')
@click.option('--quantity', type=int, default=1, help='Sequence mode: The quantity that you need')
@click.option('--start-from', type=int, default=1, help='Sequence mode: Start from sequence index')
@click.option('--prefix', type=str, default='n', help='Sequence mode: A prefix per each signed item')
@click.option('--length', type=int, default=6, help='Sequence mode: Max digit length')
@click.option('-dtf', '--dump-to-file', default=False, flag_value=True, help='Dump cert key and private key to file')
@cert_attributes_factory(False)
@out_dir_opts_factory("signed-certs")
def gen_signed_cert(cert_key, private_key, intermediate_code: str, fn: str, items: list, dump_to_file: bool,
                    seq: bool, quantity: int, start_from: int, prefix: str, length: int,
                    output_opts: OutputOpts, cert_attributes: CertAttributes):
    """
    Generate Signed certificate
    """
    if not seq and not items:
        raise RuntimeError('Must provide singed certification name')
    if seq:
        if quantity <= 0 or start_from <= 0 or length <= 0:
            raise RuntimeError('Invalid value in sequence mode. All of [quantity, start_from, length] must be > 0')
        seq_format = f'0{length}d'
        items = [f'{prefix}{x:{seq_format}}' for x in range(start_from, start_from + quantity)]
    outputs = {}
    ca_crt, ca_pkey = __load_key(cert_key, private_key)
    for item in items:
        outputs[item] = __gen_cert(f'{item}.{fn}.{intermediate_code}', cert_attributes, ca_crt, ca_pkey)
        if dump_to_file:
            FileHelper.write_file(output_opts.make_file(f"{item}.key"), outputs[item]['private_key'])
            FileHelper.write_file(output_opts.make_file(f"{item}.crt"), outputs[item]['cert_key'])
    JsonHelper.dump(output_opts.make_file(f"{intermediate_code}-{output_opts.file}.json"), outputs)


def __load_key(cert_key, private_key):
    with open(cert_key, 'rb') as f:
        ca_crt = x509.load_pem_x509_certificate(data=f.read(), backend=crypto_default_backend())
    with open(private_key, 'rb') as f:
        ca_pkey = load_pem_private_key(data=f.read(), password=None, backend=crypto_default_backend())
    return ca_crt, ca_pkey


def __gen_cert(subject_name: str, cert_attributes: CertAttributes, ca_crt: Certificate, ca_pkey):
    now = datetime.datetime.utcnow()
    crypto_backend = crypto_default_backend()
    algorithm = hashes.SHA256()
    subject = cert_attributes.create_x509_attributes(subject_name)
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=crypto_backend)
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(user_key, algorithm, crypto_backend)
    crt = x509.CertificateBuilder() \
        .subject_name(csr.subject).issuer_name(ca_crt.subject).public_key(csr.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=cert_attributes.valid_days)) \
        .add_extension(extval=x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                            content_commitment=True, data_encipherment=False,
                                            key_agreement=False, encipher_only=False,
                                            decipher_only=False, key_cert_sign=False, crl_sign=False),
                       critical=True) \
        .add_extension(extval=x509.BasicConstraints(ca=False, path_length=None), critical=True) \
        .add_extension(extval=x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pkey.public_key()),
                       critical=False) \
        .sign(private_key=ca_pkey, algorithm=hashes.SHA256(), backend=crypto_backend)
    return {
        'fqdn': subject_name,
        'private_key': __serialize_private_key(user_key),
        'cert_key': crt.public_bytes(encoding=crypto_serialization.Encoding.PEM).decode(DEFAULT_ENCODING),
        'serial_number': f'{crt.serial_number:0>40X}'
    }


def __do_encrypt(value, algorithm="sha256", enabled_base64=False):
    hash_algorithm = hashes.MD5() if algorithm == "md5" else hashes.SHA1() if algorithm == "sha1" else hashes.SHA256()
    digest = hashes.Hash(hash_algorithm, crypto_default_backend())
    digest.update(value.encode("utf-8"))
    encrypt = digest.finalize()
    return TextHelper.encode_base64(encrypt) if enabled_base64 else encrypt.hex()


def __serialize_private_key(private_key):
    return private_key.private_bytes(crypto_serialization.Encoding.PEM,
                                     crypto_serialization.PrivateFormat.TraditionalOpenSSL,
                                     crypto_serialization.NoEncryption()).decode(DEFAULT_ENCODING)


if __name__ == '__main__':
    cli()
