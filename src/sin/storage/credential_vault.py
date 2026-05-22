import os
from cryptography.fernet import Fernet
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from sin.storage.database import SessionLocal, Base
from sin.utils.logger import get_logger
from datetime import datetime

def _load_or_create_key():
    if 'CREDENTIAL_ENCRYPTION_KEY' in os.environ:
        return os.environ['CREDENTIAL_ENCRYPTION_KEY'].encode()
    elif os.path.exists('/var/lib/sin/.vault_key'):
        with open('/var/lib/sin/.vault_key', 'rb') as f:
            return f.read()
    else:
        os.makedirs('/var/lib/sin/', exist_ok=True)
        key = Fernet.generate_key()
        with open('/var/lib/sin/.vault_key', 'wb') as f:
            f.write(key)
        return key

_FERNET_KEY = _load_or_create_key()
cipher_suite = Fernet(_FERNET_KEY)

class DeviceCredential(Base):
    __tablename__ = 'device_credentials'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    username = Column(String, nullable=False)
    password_encrypted = Column(String, nullable=False)
    protocol = Column(String, default='onvif')
    priority = Column(Integer, default=0)
    last_success = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class CredentialVault:
    def __init__(self):
        pass

    def add(self, ip, vendor, username, password, protocol='onvif', priority=0):
        db = SessionLocal()
        try:
            credential = DeviceCredential(
                ip_address=ip,
                vendor=vendor,
                username=username,
                password_encrypted=self.encrypt(password),
                protocol=protocol,
                priority=priority
            )
            db.add(credential)
            db.commit()
            db.refresh(credential)
            result = {'id': credential.id, 'ip_address': credential.ip_address, 'vendor': credential.vendor, 'username': credential.username, 'protocol': credential.protocol, 'priority': credential.priority}
            return result
        finally:
            db.close()

    def get_for_device(self, ip):
        db = SessionLocal()
        try:
            ip_creds = db.query(DeviceCredential).filter_by(ip_address=ip).all()
            vendor_creds = db.query(DeviceCredential).filter_by(ip_address=None).all()
            return sorted([{
                'id': c.id,
                'ip_address': c.ip_address,
                'vendor': c.vendor,
                'username': c.username,
                'password': self.decrypt(c.password_encrypted),
                'protocol': c.protocol,
                'priority': c.priority,
                'last_success': str(c.last_success) if c.last_success else None,
                'created_at': str(c.created_at) if c.created_at else None,
            } for c in ip_creds + vendor_creds], key=lambda x: x['priority'], reverse=True)
        finally:
            db.close()

    def get_for_vendor(self, vendor):
        db = SessionLocal()
        try:
            creds = db.query(DeviceCredential).filter_by(vendor=vendor).all()
            return [{
                'id': c.id,
                'ip_address': c.ip_address,
                'vendor': c.vendor,
                'username': c.username,
                'password': self.decrypt(c.password_encrypted),
                'protocol': c.protocol,
                'priority': c.priority,
            } for c in creds]
        finally:
            db.close()

    def mark_success(self, credential_id, ip):
        db = SessionLocal()
        try:
            c = db.query(DeviceCredential).filter_by(id=credential_id).first()
            if c:
                c.last_success = datetime.now()
                db.commit()
        finally:
            db.close()

    def delete(self, credential_id):
        db = SessionLocal()
        try:
            c = db.query(DeviceCredential).filter_by(id=credential_id).first()
            if c:
                db.delete(c)
                db.commit()
        finally:
            db.close()

    def encrypt(self, plaintext: str) -> str:
        return cipher_suite.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return cipher_suite.decrypt(ciphertext.encode()).decode()

logger = get_logger(__name__)
vault = CredentialVault()
