from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class RegisterModel(BaseModel):
	username: str
	email: EmailStr
	password: str


class LoginModel(BaseModel):
	username: str
	password: str


class EmailAnalyzeModel(BaseModel):
	remetente: str
	assunto: str
	corpo: str
	spf: Optional[str] = "NONE"
	dkim: Optional[str] = "NONE"
	dmarc: Optional[str] = "NONE"

class ResponseModel(BaseModel):
	success: bool
	message: str
	date: Optional[dict] = None


class IMAPModel(BaseModel):
	email: EmailStr
	password: str
	limit: Optional[int] = 20
