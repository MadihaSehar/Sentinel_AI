import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    authorization_reference: str | None = Field(
        default=None,
        description="Link or note describing how authorization was granted "
        "(bug bounty program page, signed SOW reference, lab environment, etc.)",
    )


class ProjectRead(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    authorization_reference: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
