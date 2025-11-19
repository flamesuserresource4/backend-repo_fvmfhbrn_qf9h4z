"""
Database Schemas for the SaaS MVP

Each Pydantic model corresponds to a MongoDB collection.
Collection name is the lowercase of the class name.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class SaaSUser(BaseModel):
    email: EmailStr
    password_hash: str
    name: Optional[str] = None
    onboarding: Optional[Dict[str, Any]] = None
    plan: str = Field(default="free")  # free, pro, agency
    role: str = Field(default="user")  # user, admin
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Business(BaseModel):
    user_id: str
    name: str
    address: Optional[str] = None
    category: Optional[str] = None
    website: Optional[str] = None
    source: Optional[str] = None  # overpass, manual, import
    score: Optional[float] = None
    issues: Optional[List[str]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Analysis(BaseModel):
    user_id: str
    business_id: str
    url: str
    score: float
    summary: str
    recommendations: List[str]
    metrics: Dict[str, Any]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Proposal(BaseModel):
    user_id: str
    business_id: str
    structure: Dict[str, Any]  # renderable JSON sections
    html_preview: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
