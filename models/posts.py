from pydantic import BaseModel, Field
from datetime import datetime
import uuid
from .user import BaseUserModel


class ReturnPostModel(BaseModel):
    id: str
    creator: BaseUserModel
    image: str
    description: str
    created: datetime


class BaseCreatePostModel(BaseModel):
    image: str
    description: str


class BaseDeletePostModel(BaseModel):
    id: str
    are_you_sure: bool


class CreatePostModel(BaseCreatePostModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    creator_id: str
    created: datetime = Field(default_factory=datetime.now)
