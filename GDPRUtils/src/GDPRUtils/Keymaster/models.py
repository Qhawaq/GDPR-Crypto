from pydantic import BaseModel


class User(BaseModel):
    id: str
    shk: str
    otp_seed: str
    name: str
