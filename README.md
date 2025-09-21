# JWT Authentication with Next.js Frontend and Rails 8 API Backend

This tutorial covers implementing JWT-based authentication between a Next.js frontend and a Rails 8 API backend using Devise JWT. The system provides secure user registration, login, and protected API endpoints.

## Table of Contents

1. [Overview](#overview)
2. [Backend Configuration (Rails 8 API)](#backend-configuration-rails-8-api)
3. [Frontend Configuration (Next.js)](#frontend-configuration-nextjs)
4. [Authentication Flow](#authentication-flow)
5. [API Endpoints](#api-endpoints)
6. [Security Considerations](#security-considerations)
7. [Troubleshooting](#troubleshooting)

## Overview

Our authentication system uses:
- **Rails 8 API** with Devise and Devise JWT for backend authentication
- **Next.js** with React Context for frontend state management
- **JWT tokens** for stateless authentication
- **Role-based access control** (Admin/User roles)
- **CORS configuration** for cross-origin requests

## Backend Configuration (Rails 8 API)

### 1. Add Required Gems

Add these gems to your `Gemfile`:

```ruby
# Authentication
gem "devise"
gem "devise-jwt"
```

Run `bundle install` to install the gems.

### 2. Generate Devise Configuration

```bash
rails generate devise:install
rails generate devise User
rails generate devise:views
```

### 3. Configure Devise JWT

Create or update `config/initializers/devise.rb`:

```ruby
Devise.setup do |config|
  # ... existing Devise configuration ...

  config.jwt do |jwt|
    jwt.secret = Rails.application.secret_key_base
    jwt.dispatch_requests = [
      ['POST', %r{^/api/v1/auth/sign_in$}],
      ['POST', %r{^/api/v1/auth/sign_up$}]
    ]
    jwt.revocation_requests = [
      ['DELETE', %r{^/api/v1/auth/sign_out$}]
    ]
    jwt.expiration_time = 1.day.to_i
  end
end
```

### 4. User Model Configuration

Update `app/models/user.rb`:

```ruby
class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::JTIMatcher
  
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :jwt_authenticatable, jwt_revocation_strategy: self

  enum :role, {
    user: 0,   # Customer accounts
    admin: 1   # System configuration access
  }

  has_many :sermons, dependent: :destroy

  validates :first_name, presence: true
  validates :last_name, presence: true
  validates :role, presence: true

  before_create :assign_default_role

  def full_name
    "#{first_name} #{last_name}".strip
  end

  def admin?
    role == 'admin'
  end

  def customer?
    role == 'user'
  end

  private

  def assign_default_role
    self.role ||= :user
  end
end
```

### 5. Database Migration

Create a migration for the User model with custom fields:

```ruby
class DeviseCreateUsers < ActiveRecord::Migration[8.0]
  def change
    create_table :users do |t|
      ## Database authenticatable
      t.string :email,              null: false, default: ""
      t.string :encrypted_password, null: false, default: ""

      ## Recoverable
      t.string   :reset_password_token
      t.datetime :reset_password_sent_at

      ## Rememberable
      t.datetime :remember_created_at

      ## Custom fields
      t.string :first_name
      t.string :last_name
      t.integer :role, default: 0, null: false
      t.string :jti, null: false

      t.timestamps null: false
    end

    add_index :users, :email,                unique: true
    add_index :users, :reset_password_token, unique: true
    add_index :users, :jti,                  unique: true
  end
end
```

### 6. CORS Configuration

Update `config/initializers/cors.rb`:

```ruby
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins "http://localhost:8000"  # Next.js frontend

    resource "*",
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head],
      expose_headers: ['Authorization', 'authorization', 'Content-Type']
  end
end
```

### 7. Custom Authentication Controllers

#### Registration Controller

Create `app/controllers/api/v1/auth/registrations_controller.rb`:

```ruby
class Api::V1::Auth::RegistrationsController < Devise::RegistrationsController
  include RackSessionsFix
  respond_to :json

  private

  def respond_with(current_user, _opts = {})
    if resource.persisted?
      # Generate JWT token manually for response body
      jwt_payload = { 
        sub: resource.id.to_s, 
        jti: resource.jti, 
        scp: 'api_v1_user',
        aud: nil,
        iat: Time.current.to_i,
        exp: 1.day.from_now.to_i
      }
      token = JWT.encode(jwt_payload, Rails.application.secret_key_base, 'HS256')
      
      render json: {
        status: { code: 200, message: 'Signed up successfully.' },
        data: UserSerializer.new(resource).serializable_hash[:data][:attributes],
        token: token
      }
    else
      render json: {
        status: { message: "User couldn't be created successfully. #{resource.errors.full_messages.to_sentence}" }
      }, status: :unprocessable_entity
    end
  end

  def sign_up_params
    params.require(:user).permit(:first_name, :last_name, :email, :password, :password_confirmation)
  end
end
```

#### Sessions Controller

Create `app/controllers/api/v1/auth/sessions_controller.rb`:

```ruby
class Api::V1::Auth::SessionsController < Devise::SessionsController
  include RackSessionsFix
  respond_to :json

  private

  def respond_with(current_user, _opts = {})
    user = resource || current_user
    
    jwt_payload = { 
      sub: user.id.to_s, 
      jti: user.jti, 
      scp: 'api_v1_user',
      aud: nil,
      iat: Time.current.to_i,
      exp: 1.day.from_now.to_i
    }
    token = JWT.encode(jwt_payload, Rails.application.secret_key_base, 'HS256')
    
    render json: {
      status: { 
        code: 200, 
        message: 'Logged in successfully.',
        data: { user: UserSerializer.new(user).serializable_hash[:data][:attributes] }
      },
      token: token
    }, status: :ok
  end

  def respond_to_on_destroy
    if request.headers['Authorization'].present?
      jwt_payload = JWT.decode(request.headers['Authorization'].split(' ').last, Rails.application.secret_key_base).first
      current_user = User.find(jwt_payload['sub'])
    end
    
    if current_user
      render json: {
        status: { 
          code: 200,
          message: 'Logged out successfully.'
        }
      }, status: :ok
    else
      render json: {
        status: { 
          code: 401,
          message: "Couldn't find an active session."
        }
      }, status: :unauthorized
    end
  end
end
```

#### Rack Sessions Fix

Create `app/controllers/concerns/rack_sessions_fix.rb`:

```ruby
module RackSessionsFix
  extend ActiveSupport::Concern

  class FakeRackSession < Hash
    def enabled?
      false
    end

    def destroy; end
  end

  included do
    before_action :set_fake_session

    private

    def set_fake_session
      request.env['rack.session'] = FakeRackSession.new
    end
  end
end
```

### 8. User Serializer

Create `app/serializers/user_serializer.rb`:

```ruby
class UserSerializer
  include JSONAPI::Serializer
  attributes :id, :email, :first_name, :last_name, :role, :created_at, :full_name
end
```

### 9. Application Controller

Update `app/controllers/application_controller.rb`:

```ruby
class ApplicationController < ActionController::API
  before_action :configure_permitted_parameters, if: :devise_controller?

  def authenticate_user!
    header = request.headers['Authorization']
    header = header.split(' ').last if header
    
    begin
      @decoded = JWT.decode(header, Rails.application.secret_key_base).first
      @current_user = User.find(@decoded['sub'])
    rescue JWT::DecodeError => e
      render json: { errors: ['Invalid token'] }, status: :unauthorized
    rescue ActiveRecord::RecordNotFound => e
      render json: { errors: ['User not found'] }, status: :unauthorized
    end
  end

  def current_user
    @current_user
  end

  def require_admin!
    unless current_user&.admin?
      render json: { errors: ['Admin access required'] }, status: :forbidden
    end
  end

  private

  def configure_permitted_parameters
    devise_parameter_sanitizer.permit(:sign_up, keys: [:first_name, :last_name])
    devise_parameter_sanitizer.permit(:account_update, keys: [:first_name, :last_name])
  end
end
```

### 10. Routes Configuration

Update `config/routes.rb`:

```ruby
Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  namespace :api do
    namespace :v1 do
      devise_for :users, path: 'auth', controllers: {
        sessions: 'api/v1/auth/sessions',
        registrations: 'api/v1/auth/registrations'
      }, path_names: {
        sign_in: 'sign_in',
        sign_out: 'sign_out',
        registration: 'sign_up'
      }
      
      resources :sermons do
        member do
          get :summary
          post :retry_transcription
          get :debug_logs
        end
      end
      
      resources :lessons
      get 'debug/system_logs', to: 'debug#system_logs'
    end
  end
  
  require "sidekiq/web"
  mount Sidekiq::Web => "/sidekiq"
end
```

### 11. Protect API Endpoints

Update your API controllers to require authentication:

```ruby
class Api::V1::SermonsController < ApplicationController
  before_action :authenticate_user!
  before_action :set_sermon, only: [:show, :summary, :destroy, :retry_transcription, :debug_logs]

  def index
    @sermons = current_user.sermons.includes(:series, :transcript, :chapters, :scripture_references)
                           .order(created_at: :desc)
    # ... rest of implementation
  end

  def create
    @sermon = current_user.sermons.build(sermon_params)
    @sermon.status = :pending
    # ... rest of implementation
  end

  private

  def set_sermon
    @sermon = current_user.sermons.find(params[:id])
  rescue ActiveRecord::RecordNotFound
    render json: {
      errors: [{ detail: 'Sermon not found' }]
    }, status: :not_found
  end
end
```

## Frontend Configuration (Next.js)

### 1. Authentication Context

Create `src/contexts/AuthContext.tsx`:

```typescript
'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

interface User {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  full_name: string;
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<boolean>;
  register: (userData: RegisterData) => Promise<boolean>;
  logout: () => void;
  loading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
}

interface RegisterData {
  email: string;
  password: string;
  password_confirmation: string;
  first_name: string;
  last_name: string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      verifyToken(token);
    } else {
      setLoading(false);
    }
  }, []);

  const verifyToken = async (token: string) => {
    try {
      const response = await fetch('http://localhost:8500/api/v1/sermons', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const payload = JSON.parse(atob(token.split('.')[1]));
        setUser({
          id: payload.sub,
          email: payload.email || '',
          first_name: payload.first_name || '',
          last_name: payload.last_name || '',
          role: payload.role || 'user',
          full_name: `${payload.first_name || ''} ${payload.last_name || ''}`.trim()
        });
      } else {
        localStorage.removeItem('auth_token');
        setUser(null);
      }
    } catch (error) {
      console.error('Token verification failed:', error);
      localStorage.removeItem('auth_token');
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const response = await fetch('http://localhost:8500/api/v1/auth/sign_in', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user: { email, password }
        }),
      });

      if (response.ok) {
        const data = await response.json();
        let token = response.headers.get('authorization') || response.headers.get('Authorization');
        if (!token && data.token) {
          token = `Bearer ${data.token}`;
        }
        
        if (token) {
          localStorage.setItem('auth_token', token.replace('Bearer ', ''));
          setUser(data.status.data.user);
          router.push('/sermons');
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const register = async (userData: RegisterData): Promise<boolean> => {
    try {
      const response = await fetch('http://localhost:8500/api/v1/auth/sign_up', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ user: userData }),
      });

      if (response.ok) {
        const data = await response.json();
        let token = response.headers.get('authorization') || response.headers.get('Authorization');
        if (!token && data.token) {
          token = `Bearer ${data.token}`;
        }
        
        if (token) {
          localStorage.setItem('auth_token', token.replace('Bearer ', ''));
          setUser(data.data);
          router.push('/sermons');
          return true;
        }
      } else {
        const errorData = await response.json();
        console.error('Registration failed with response:', errorData);
      }
      return false;
    } catch (error) {
      console.error('Registration failed:', error);
      return false;
    }
  };

  const logout = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      if (token) {
        await fetch('http://localhost:8500/api/v1/auth/sign_out', {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('auth_token');
      setUser(null);
      router.push('/');
    }
  };

  const value = {
    user,
    login,
    register,
    logout,
    loading,
    isAuthenticated: !!user,
    isAdmin: user?.role === 'admin'
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

### 2. Layout Configuration

Update your root layout to include the AuthProvider:

```typescript
// src/app/layout.tsx
import { AuthProvider } from "@/contexts/AuthContext";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
        <AuthProvider>
          <Navigation />
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

### 3. Login Page

Create `src/app/login/page.tsx`:

```typescript
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  const { login } = useAuth();
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const success = await login(email, password);
      if (!success) {
        setError('Invalid email or password. Please try again.');
      }
    } catch (error) {
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="text-center text-4xl mb-4">📚</div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Or{' '}
            <Link href="/register" className="font-medium text-blue-600 hover:text-blue-500">
              create a new account
            </Link>
          </p>
        </div>
        
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="email" className="sr-only">
                Email address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="relative block w-full rounded-t-md border-0 py-1.5 text-gray-900 ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:z-10 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 px-3"
                placeholder="Email address"
              />
            </div>
            <div>
              <label htmlFor="password" className="sr-only">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="relative block w-full rounded-b-md border-0 py-1.5 text-gray-900 ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:z-10 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 px-3"
                placeholder="Password"
              />
            </div>
          </div>

          {error && (
            <div className="rounded-md bg-red-50 p-4">
              <div className="text-sm text-red-700">{error}</div>
            </div>
          )}

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-blue-400 disabled:cursor-not-allowed"
            >
              {loading ? (
                <div className="flex items-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Signing in...
                </div>
              ) : (
                'Sign in'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
```

### 4. Registration Page

Create `src/app/register/page.tsx`:

```typescript
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';

export default function Register() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    password_confirmation: '',
    first_name: '',
    last_name: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  const { register } = useAuth();
  const router = useRouter();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (formData.password !== formData.password_confirmation) {
      setError('Passwords do not match.');
      setLoading(false);
      return;
    }

    try {
      const success = await register(formData);
      if (!success) {
        setError('Registration failed. Please check your information and try again.');
      }
    } catch (error) {
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="text-center text-4xl mb-4">📚</div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Create your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Or{' '}
            <Link href="/login" className="font-medium text-blue-600 hover:text-blue-500">
              sign in to existing account
            </Link>
          </p>
        </div>
        
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="first_name" className="block text-sm font-medium text-gray-700">
                  First Name
                </label>
                <input
                  id="first_name"
                  name="first_name"
                  type="text"
                  required
                  value={formData.first_name}
                  onChange={handleChange}
                  className="mt-1 block w-full rounded-md border-0 py-1.5 text-gray-900 ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 px-3"
                  placeholder="First name"
                />
              </div>
              <div>
                <label htmlFor="last_name" className="block text-sm font-medium text-gray-700">
                  Last Name
                </label>
                <input
                  id="last_name"
                  name="last_name"
                  type="text"
                  required
                  value={formData.last_name}
                  onChange={handleChange}
                  className="mt-1 block w-full rounded-md border-0 py-1.5 text-gray-900 ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 px-3"
                  placeholder="Last name"
                />
              </div>
            </div>
            
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email Address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={formData.email}
                onChange={handleChange}
                className="mt-1 block w-full rounded-md border-0 py-1.5 text-gray-900 ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 px-3"
                placeholder="Email address"
              />
            </div>
            
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                required
                value={formData.password}
                onChange={handleChange}
                className="mt-1 block w-full rounded-md border-0 py-1.5 text-gray-900 ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 px-3"
                placeholder="Password"
              />
            </div>
            
            <div>
              <label htmlFor="password_confirmation" className="block text-sm font-medium text-gray-700">
                Confirm Password
              </label>
              <input
                id="password_confirmation"
                name="password_confirmation"
                type="password"
                autoComplete="new-password"
                required
                value={formData.password_confirmation}
                onChange={handleChange}
                className="mt-1 block w-full rounded-md border-0 py-1.5 text-gray-900 ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 px-3"
                placeholder="Confirm password"
              />
            </div>
          </div>

          {error && (
            <div className="rounded-md bg-red-50 p-4">
              <div className="text-sm text-red-700">{error}</div>
            </div>
          )}

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-blue-400 disabled:cursor-not-allowed"
            >
              {loading ? (
                <div className="flex items-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Creating account...
                </div>
              ) : (
                'Create account'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
```

### 5. Protected Routes

For protected pages, add authentication checks:

```typescript
// Example: src/app/sermons/page.tsx
'use client';

import { useAuth } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

export default function SermonsPage() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const router = useRouter();

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      router.push('/login');
    }
  }, [isAuthenticated, authLoading, router]);

  if (authLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return null; // Will redirect
  }

  // Helper function to get headers with authentication
  const getAuthHeaders = () => {
    const token = localStorage.getItem('auth_token');
    return {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` })
    };
  };

  const fetchSermons = async () => {
    const response = await fetch('http://localhost:8500/api/v1/sermons', {
      headers: getAuthHeaders()
    });
    // ... handle response
  };

  return (
    <div>
      {/* Your protected content */}
    </div>
  );
}
```

### 6. Navigation Component

Update your navigation to show authentication state:

```typescript
// src/components/Navigation.tsx
import { useAuth } from '@/contexts/AuthContext';

export default function Navigation() {
  const { user, logout, isAuthenticated, loading } = useAuth();

  return (
    <nav className="bg-white shadow-lg">
      <div className="container mx-auto px-4">
        <div className="flex justify-between items-center h-16">
          <Link href="/" className="flex items-center space-x-2">
            <div className="text-2xl">📚</div>
            <span className="text-xl font-bold text-gray-900">
              Sermon Curriculum AI
            </span>
          </Link>

          <div className="flex items-center space-x-8">
            {loading ? (
              <div className="animate-pulse bg-gray-200 h-8 w-20 rounded"></div>
            ) : isAuthenticated ? (
              <div className="flex items-center space-x-4">
                <span className="text-sm text-gray-600">
                  Welcome, {user?.first_name}
                  {user?.role === 'admin' && (
                    <span className="ml-1 inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-purple-100 text-purple-800">
                      Admin
                    </span>
                  )}
                </span>
                <button
                  onClick={logout}
                  className="text-gray-600 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium transition-colors"
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <div className="flex space-x-4">
                <Link
                  href="/login"
                  className="text-gray-600 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  href="/register"
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium transition-colors"
                >
                  Sign Up
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}
```

## Authentication Flow

### 1. Registration Flow

1. User fills out registration form
2. Frontend sends POST request to `/api/v1/auth/sign_up`
3. Backend creates user and returns JWT token in response body
4. Frontend stores token in localStorage and updates auth state
5. User is redirected to protected page (e.g., `/sermons`)

### 2. Login Flow

1. User enters credentials
2. Frontend sends POST request to `/api/v1/auth/sign_in`
3. Backend validates credentials and returns JWT token
4. Frontend stores token and updates auth state
5. User is redirected to protected page

### 3. Protected API Calls

1. Frontend retrieves token from localStorage
2. Adds `Authorization: Bearer <token>` header to API requests
3. Backend validates JWT token and sets `current_user`
4. API responds with user-specific data

### 4. Logout Flow

1. Frontend sends DELETE request to `/api/v1/auth/sign_out`
2. Backend revokes JWT token
3. Frontend removes token from localStorage and clears auth state
4. User is redirected to home page

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/auth/sign_up` | User registration | No |
| POST | `/api/v1/auth/sign_in` | User login | No |
| DELETE | `/api/v1/auth/sign_out` | User logout | Yes |

### Protected Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/sermons` | List user's sermons | Yes |
| POST | `/api/v1/sermons` | Create new sermon | Yes |
| GET | `/api/v1/sermons/:id` | Get sermon details | Yes |
| DELETE | `/api/v1/sermons/:id` | Delete sermon | Yes |

## Security Considerations

### 1. JWT Token Security

- Tokens are stored in localStorage (consider httpOnly cookies for production)
- Tokens expire after 1 day
- JTI (JWT ID) is used for token revocation
- Secret key is derived from Rails secret_key_base

### 2. CORS Configuration

- Only allows requests from specified frontend origin
- Exposes necessary headers for JWT authentication
- Configures allowed HTTP methods

### 3. User Isolation

- All API endpoints are scoped to `current_user`
- Users can only access their own data
- Admin role provides system-level access

### 4. Input Validation

- Devise provides built-in email/password validation
- Custom validations for required fields
- Parameter sanitization in controllers

## Troubleshooting

### Common Issues

#### 1. 401 Unauthorized Errors

**Symptoms:** API calls return 401 status
**Causes:**
- Missing or invalid JWT token
- Token expired
- CORS issues preventing token transmission

**Solutions:**
- Check if token is stored in localStorage
- Verify token format: `Bearer <token>`
- Ensure CORS exposes `Authorization` header
- Check token expiration time

#### 2. CORS Issues

**Symptoms:** Browser blocks requests due to CORS policy
**Solutions:**
- Verify `config/initializers/cors.rb` configuration
- Ensure `expose_headers` includes `Authorization`
- Check frontend origin matches CORS allowed origins

#### 3. Token Not Found in Headers

**Symptoms:** Backend can't find JWT token in request headers
**Solutions:**
- Use `Authorization` header (not `authorization`)
- Include `Bearer ` prefix before token
- Check if token is being sent from frontend

#### 4. User Data Empty in Login Response

**Symptoms:** Login succeeds but user data is null/empty
**Solutions:**
- Use `resource` instead of `current_user` in sessions controller
- Verify UserSerializer is properly configured
- Check if user exists in database

### Debugging Tips

1. **Check Browser Network Tab:**
   - Verify request headers include Authorization
   - Check response status and body
   - Look for CORS preflight requests

2. **Check Rails Logs:**
   - Look for authentication errors
   - Verify JWT token decoding
   - Check user lookup queries

3. **Check Frontend Console:**
   - Look for JavaScript errors
   - Verify localStorage contains token
   - Check auth state updates

4. **Test with curl:**
   ```bash
   # Test registration
   curl -X POST "http://localhost:8500/api/v1/auth/sign_up" \
     -H "Content-Type: application/json" \
     -d '{"user": {"email": "test@example.com", "password": "password123", "password_confirmation": "password123", "first_name": "Test", "last_name": "User"}}'

   # Test protected endpoint
   curl -X GET "http://localhost:8500/api/v1/sermons" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
   ```

### Environment Variables

Make sure these are set in your environment:

```bash
# Rails backend
JWT_SECRET_KEY=your_jwt_secret_key  # Optional, defaults to secret_key_base

# Next.js frontend
NEXT_PUBLIC_API_URL=http://localhost:8500
```

## Conclusion

This JWT authentication system provides:

- ✅ Secure user registration and login
- ✅ Stateless authentication with JWT tokens
- ✅ Role-based access control
- ✅ Protected API endpoints
- ✅ Cross-origin request support
- ✅ Token expiration and revocation

The system is production-ready with proper security measures and can be extended with additional features like password reset, email verification, and more granular permissions.
