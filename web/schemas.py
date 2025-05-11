"""
Schema definitions for request and response validation.
Uses Pydantic for data validation, serialization, and documentation.
"""

from typing import Dict, List, Optional, Union, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field, validator, EmailStr, HttpUrl, constr


class ErrorResponse(BaseModel):
    """Schema for error responses"""
    status: Literal["error"]
    message: str
    code: int
    details: Optional[Dict[str, Any]] = None


class SuccessResponse(BaseModel):
    """Schema for success responses"""
    status: Literal["success"]
    message: str
    data: Optional[Dict[str, Any]] = None


class TaskCreate(BaseModel):
    """Schema for creating a new task"""
    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    module: str = Field(..., min_length=3, max_length=100)
    target: str = Field(..., min_length=1, max_length=255)
    options: Optional[Dict[str, Any]] = Field(None)
    priority: Optional[int] = Field(3, ge=1, le=5)
    tags: Optional[List[str]] = Field(None)
    
    @validator('module')
    def validate_module(cls, v):
        """Validate module format"""
        if not '.' in v:
            raise ValueError('Module must be in format category.name')
        return v
    
    @validator('tags', pre=True)
    def validate_tags(cls, v):
        """Convert comma-separated string to list"""
        if isinstance(v, str):
            return [tag.strip() for tag in v.split(',') if tag.strip()]
        return v


class TaskUpdate(BaseModel):
    """Schema for updating an existing task"""
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    status: Optional[str] = Field(None)
    options: Optional[Dict[str, Any]] = Field(None)
    priority: Optional[int] = Field(None, ge=1, le=5)
    tags: Optional[List[str]] = Field(None)
    
    @validator('status')
    def validate_status(cls, v):
        """Validate status value"""
        valid_statuses = ['scheduled', 'running', 'completed', 'failed', 'cancelled']
        if v not in valid_statuses:
            raise ValueError(f'Status must be one of: {", ".join(valid_statuses)}')
        return v
    
    @validator('tags', pre=True)
    def validate_tags(cls, v):
        """Convert comma-separated string to list"""
        if isinstance(v, str):
            return [tag.strip() for tag in v.split(',') if tag.strip()]
        return v


class TaskStatusRequest(BaseModel):
    """Schema for requesting status of multiple tasks"""
    task_ids: List[str] = Field(..., min_items=1)


class UserCreate(BaseModel):
    """Schema for creating a new user"""
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    email: EmailStr
    password: str = Field(..., min_length=8)
    confirm_password: str
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        """Validate that passwords match"""
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v


class UserLogin(BaseModel):
    """Schema for user login"""
    username: str
    password: str


class UserUpdate(BaseModel):
    """Schema for updating user information"""
    email: Optional[EmailStr] = None
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=8)
    confirm_password: Optional[str] = None
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        """Validate that passwords match"""
        if 'new_password' in values and values['new_password'] and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('new_password')
    def password_required_fields(cls, v, values, **kwargs):
        """Validate that current_password is provided when changing password"""
        if v and not values.get('current_password'):
            raise ValueError('Current password is required when changing password')
        return v


class ScanConfigCreate(BaseModel):
    """Schema for creating a new scan configuration"""
    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    modules: List[str] = Field(..., min_items=1)
    options: Dict[str, Dict[str, Any]] = Field(...)
    is_default: Optional[bool] = Field(False)
    
    @validator('modules')
    def validate_modules(cls, v):
        """Validate module format"""
        for module in v:
            if not '.' in module:
                raise ValueError(f'Module {module} must be in format category.name')
        return v


class ScanConfigUpdate(BaseModel):
    """Schema for updating a scan configuration"""
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    modules: Optional[List[str]] = Field(None, min_items=1)
    options: Optional[Dict[str, Dict[str, Any]]] = Field(None)
    is_default: Optional[bool] = Field(None)
    
    @validator('modules')
    def validate_modules(cls, v):
        """Validate module format"""
        if v:
            for module in v:
                if not '.' in module:
                    raise ValueError(f'Module {module} must be in format category.name')
        return v


class ReportCreate(BaseModel):
    """Schema for creating a new report"""
    title: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    task_ids: List[str] = Field(..., min_items=1)
    format: str = Field('pdf')
    template: Optional[str] = Field('default')
    
    @validator('format')
    def validate_format(cls, v):
        """Validate report format"""
        valid_formats = ['pdf', 'html', 'json', 'csv', 'xml']
        if v not in valid_formats:
            raise ValueError(f'Format must be one of: {", ".join(valid_formats)}')
        return v


class ApiKeyCreate(BaseModel):
    """Schema for creating a new API key"""
    name: str = Field(..., min_length=3, max_length=50)
    expires_at: Optional[datetime] = None
    permissions: Optional[List[str]] = None


class ApiKeyResponse(BaseModel):
    """Schema for API key response"""
    id: str
    name: str
    key: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
