# Next.js + Rails 8 + Devise JWT Authentication Tutorial

A complete guide to implementing JWT authentication between a Next.js frontend and Rails 8 API using Devise and devise-jwt.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Rails 8 API Setup](#rails-8-api-setup)
4. [Devise JWT Configuration](#devise-jwt-configuration)
5. [Next.js Frontend Setup](#nextjs-frontend-setup)
6. [Authentication Implementation](#authentication-implementation)
7. [CORS Configuration](#cors-configuration)
8. [Testing the Setup](#testing-the-setup)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

## Overview

This tutorial demonstrates how to create a secure, production-ready authentication system using:

- **Backend**: Rails 8 API with Devise and devise-jwt
- **Frontend**: Next.js with TypeScript and Axios
- **Authentication**: JWT tokens with automatic refresh and revocation
- **Security**: CORS properly configured, secure token storage

### Architecture Overview

```
┌─────────────────┐    HTTP/JSON     ┌─────────────────┐
│                 │   + JWT Token    │                 │
│   Next.js App   │ ◄──────────────► │   Rails 8 API   │
│  (Frontend)     │                  │   (Backend)     │
│                 │                  │                 │
└─────────────────┘                  └─────────────────┘
         │                                     │
         │                                     │
    localStorage                         PostgreSQL
    (JWT Token)                         (Users + JWT Denylist)
```

## Prerequisites

- **Ruby** 3.2+ with Rails 8.0+
- **Node.js** 18+ with npm
- **PostgreSQL** for database
- **Redis** for background jobs (optional)

## Rails 8 API Setup

### 1. Create Rails API Application

```bash
# Create new Rails API application
rails new my_app_api --api --database=postgresql
cd my_app_api

# Add required gems
```

### 2. Gemfile Configuration

```ruby
# Gemfile
gem 'devise'
gem 'devise-jwt', '~> 0.9'
gem 'rack-cors'
gem 'active_model_serializers'

group :development, :test do
  gem 'debug', platforms: %i[ mri mingw x64_mingw ]
  gem 'rspec-rails'
  gem 'factory_bot_rails'
end
```

```bash
bundle install
```

### 3. Database Setup

```bash
# Create and setup database
rails db:create
rails db:migrate

# Generate Devise configuration
rails generate devise:install
rails generate devise User
rails generate devise:controllers users -c=sessions,registrations

# Generate JWT denylist model
rails generate model JwtDenylist jti:string:index exp:datetime
rails db:migrate
```

## Devise JWT Configuration

### 1. JWT Denylist Model

```ruby
# app/models/jwt_denylist.rb
class JwtDenylist < ApplicationRecord
  include Devise::JWT::RevocationStrategies::Denylist

  self.table_name = 'jwt_denylists'
end
```

### 2. User Model Configuration

```ruby
# app/models/user.rb
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :jwt_authenticatable, jwt_revocation_strategy: JwtDenylist

  # Add any additional associations and methods
  def admin?
    # Implement your role logic
    false
  end
end
```

### 3. Devise Initializer

```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  # ... existing Devise configuration ...

  # ==> JWT Configuration
  if ENV['JWT_SECRET_KEY'].present?
    config.jwt do |jwt|
      jwt.secret = ENV['JWT_SECRET_KEY']
      jwt.dispatch_requests = [
        ['POST', %r{^/users/sign_in$}]
      ]
      jwt.revocation_requests = [
        ['DELETE', %r{^/users/sign_out$}]
      ]
      jwt.expiration_time = 24.hours.to_i
    end
  end
end
```

### 4. Custom Sessions Controller

```ruby
# app/controllers/users/sessions_controller.rb
class Users::SessionsController < Devise::SessionsController
  respond_to :json

  private

  def respond_with(resource, _opts = {})
    if resource.persisted?
      render json: {
        status: { code: 200, message: 'Logged in successfully.' },
        data: {
          id: resource.id,
          email: resource.email,
          created_at: resource.created_at,
          updated_at: resource.updated_at,
          roles: [], # Add your role logic here
          is_admin: resource.admin?
        }
      }
    else
      render json: {
        status: { message: "Invalid email or password." }
      }, status: :unauthorized
    end
  end

  def respond_to_on_destroy
    if current_user
      render json: {
        status: 200,
        message: "Logged out successfully."
      }
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }
    end
  end
end
```

### 5. API Controllers

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::API
  include Devise::Controllers::Helpers
  
  # Configure Devise to work with API
  before_action :configure_permitted_parameters, if: :devise_controller?
  
  protected
  
  def configure_permitted_parameters
    devise_parameter_sanitizer.permit(:sign_up, keys: [:email, :password])
    devise_parameter_sanitizer.permit(:sign_in, keys: [:email, :password])
  end
end
```

```ruby
# app/controllers/api/v1/base_controller.rb
module Api
  module V1
    class BaseController < ApplicationController
      before_action :authenticate_user!
      before_action :set_default_format

      private

      def set_default_format
        request.format = :json
      end

      def render_error(message, status = :unprocessable_entity)
        render json: { error: message }, status: status
      end

      def render_success(data, status = :ok)
        render json: data, status: status
      end
    end
  end
end
```

```ruby
# app/controllers/api/v1/users_controller.rb
class Api::V1::UsersController < Api::V1::BaseController
  def me
    render json: {
      id: current_user.id,
      email: current_user.email,
      created_at: current_user.created_at,
      updated_at: current_user.updated_at,
      roles: [], # Add your role logic
      is_admin: current_user.admin?
    }
  end
end
```

### 6. Routes Configuration

```ruby
# config/routes.rb
Rails.application.routes.draw do
  devise_for :users, controllers: {
    sessions: 'users/sessions',
    registrations: 'users/registrations'
  }

  namespace :api do
    namespace :v1 do
      # Current user endpoint
      get 'users/me', to: 'users#me'
      
      # Other API routes...
    end
  end

  # Health check
  get "health" => "health#index"
end
```

## CORS Configuration

### 1. CORS Initializer

```ruby
# config/initializers/cors.rb
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins "http://localhost:3000", "http://localhost:8080", "https://yourdomain.com"

    resource "*",
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head],
      credentials: true,
      expose: ['authorization']  # Critical: Expose JWT token header
  end
end
```

### 2. Environment Configuration

```ruby
# config/environments/development.rb
Rails.application.configure do
  # ... other configuration ...
  
  # Allow CORS in development
  config.force_ssl = false
  
  # Configure Active Storage for development
  config.active_storage.service = :local
end
```

## Next.js Frontend Setup

### 1. Install Dependencies

```bash
# Create Next.js app
npx create-next-app@latest my-app-frontend --typescript --tailwind --eslint
cd my-app-frontend

# Install additional dependencies
npm install axios
npm install @types/node
```

### 2. API Configuration (Single Source of Truth)

```typescript
// src/lib/config.ts
/**
 * Centralized API Configuration
 * Single source of truth for all API endpoints and configuration
 */

const detectApiUrl = (): string => {
  // Use environment variable if provided
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }
  
  // Default to development port
  return 'http://localhost:8081';
};

export const API_CONFIG = {
  BASE_URL: detectApiUrl(),
  VERSION: 'v1',
  PREFIX: '/api/v1'
} as const;

/**
 * Build a complete API URL for an endpoint
 * @param endpoint - The endpoint path (e.g., '/users/me', '/assets')
 * @returns Complete URL (e.g., 'http://localhost:8081/api/v1/users/me')
 */
export const buildApiUrl = (endpoint: string): string => {
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${API_CONFIG.BASE_URL}${API_CONFIG.PREFIX}${normalizedEndpoint}`;
};

/**
 * Build a non-versioned API URL (for legacy endpoints during migration)
 * @param endpoint - The endpoint path
 * @returns Complete URL without version prefix
 */
export const buildLegacyApiUrl = (endpoint: string): string => {
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${API_CONFIG.BASE_URL}${normalizedEndpoint}`;
};

/**
 * API endpoint constants for type safety and consistency
 */
export const API_ENDPOINTS = {
  // Authentication
  AUTH: {
    SIGN_IN: '/users/sign_in',
    SIGN_UP: '/users',
    ME: '/users/me'
  }
} as const;
```

### 3. Axios API Client

```typescript
// src/lib/api.ts
import axios from 'axios'
import { API_CONFIG } from './config'

export const api = axios.create({
  baseURL: API_CONFIG.BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Important for CORS with credentials
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    // Don't override Content-Type for FormData (file uploads)
    if (config.data instanceof FormData) {
      delete config.headers['Content-Type']
    }
    
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Clear invalid token
      localStorage.removeItem('auth_token')
      delete api.defaults.headers.common['Authorization']
      
      // Redirect to login (adjust based on your routing)
      if (typeof window !== 'undefined') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)
```

### 4. Authentication Hook

```typescript
// src/hooks/useAuth.tsx
'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { api } from '../lib/api'
import { buildApiUrl, buildLegacyApiUrl, API_ENDPOINTS } from '../lib/config'

interface User {
  id: number
  email: string
  created_at: string
  updated_at: string
  roles: string[]
  is_admin: boolean
}

interface AuthContextType {
  user: User | null
  loading: boolean
  login: (email: string, password: string) => Promise<boolean>
  logout: () => void
  register: (email: string, password: string) => Promise<boolean>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    try {
      const token = localStorage.getItem('auth_token')
      if (!token) {
        console.log('No token found, setting loading to false')
        setLoading(false)
        return
      }

      console.log('Checking auth status with token')
      const response = await api.get(buildApiUrl(API_ENDPOINTS.AUTH.ME), {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })

      console.log('Auth check successful, user data:', response.data)
      setUser(response.data)
    } catch (error) {
      console.error('Auth check failed:', error)
      localStorage.removeItem('auth_token')
      delete api.defaults.headers.common['Authorization']
    } finally {
      console.log('Setting loading to false')
      setLoading(false)
    }
  }

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const response = await api.post(buildLegacyApiUrl(API_ENDPOINTS.AUTH.SIGN_IN), {
        user: { email, password }
      })

      // Extract JWT token from Authorization header
      const token = response.headers['authorization']?.replace('Bearer ', '')
      if (token) {
        localStorage.setItem('auth_token', token)
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        // Get user info
        const userResponse = await api.get(buildApiUrl(API_ENDPOINTS.AUTH.ME), {
          headers: {
            Authorization: `Bearer ${token}`
          }
        })
        
        setUser(userResponse.data)
        return true
      }
      return false
    } catch (error) {
      console.error('Login failed:', error)
      return false
    }
  }

  const register = async (email: string, password: string): Promise<boolean> => {
    try {
      const response = await api.post(buildLegacyApiUrl(API_ENDPOINTS.AUTH.SIGN_UP), {
        user: { email, password }
      })

      // Handle registration response similar to login
      const token = response.headers['authorization']?.replace('Bearer ', '')
      if (token) {
        localStorage.setItem('auth_token', token)
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`
        setUser(response.data.data)
        return true
      }
      return false
    } catch (error) {
      console.error('Registration failed:', error)
      return false
    }
  }

  const logout = () => {
    localStorage.removeItem('auth_token')
    delete api.defaults.headers.common['Authorization']
    setUser(null)
    
    // Optional: Call logout endpoint to revoke token
    api.delete(buildLegacyApiUrl('/users/sign_out')).catch(console.error)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
```

### 5. Login Component

```typescript
// src/components/auth/LoginForm.tsx
'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/hooks/useAuth'

export default function LoginForm() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  
  const { login } = useAuth()
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const success = await login(email, password)
      if (success) {
        router.push('/dashboard')
      } else {
        setError('Invalid email or password')
      }
    } catch (error) {
      setError('Login failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}
          
          <div>
            <label htmlFor="email" className="sr-only">Email address</label>
            <input
              id="email"
              name="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="relative block w-full px-3 py-2 border border-gray-300 rounded-md placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
              placeholder="Email address"
            />
          </div>
          
          <div>
            <label htmlFor="password" className="sr-only">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="relative block w-full px-3 py-2 border border-gray-300 rounded-md placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
              placeholder="Password"
            />
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
```

### 6. Protected Route Wrapper

```typescript
// src/components/auth/ProtectedRoute.tsx
'use client'

import { useAuth } from '@/hooks/useAuth'
import { useRouter } from 'next/navigation'
import { useEffect } from 'react'

interface ProtectedRouteProps {
  children: React.ReactNode
  requireAdmin?: boolean
}

export default function ProtectedRoute({ children, requireAdmin = false }: ProtectedRouteProps) {
  const { user, loading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!loading) {
      if (!user) {
        router.push('/login')
        return
      }
      
      if (requireAdmin && !user.is_admin) {
        router.push('/unauthorized')
        return
      }
    }
  }, [user, loading, router, requireAdmin])

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!user || (requireAdmin && !user.is_admin)) {
    return null
  }

  return <>{children}</>
}
```

### 7. App Layout Setup

```typescript
// src/app/layout.tsx
import { AuthProvider } from '@/hooks/useAuth'
import './globals.css'

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  )
}
```

### 8. Environment Configuration

```bash
# .env.local (for development)
NEXT_PUBLIC_API_URL=http://localhost:8081
NEXT_PUBLIC_API_BASE_URL=http://localhost:8081
NEXT_PUBLIC_ENVIRONMENT=development
```

## Testing the Setup

### 1. Start Development Servers

```bash
# Terminal 1: Start Rails API
cd my_app_api
JWT_SECRET_KEY=your_development_secret_key RAILS_ENV=development rails server -p 8081

# Terminal 2: Start Next.js
cd my_app_frontend
npm run dev
```

### 2. Test Authentication Flow

```bash
# Test login endpoint
curl -X POST http://localhost:8081/users/sign_in \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"test@example.com","password":"password"}}' \
  -D headers.txt

# Check for Authorization header
grep -i authorization headers.txt

# Test protected endpoint
TOKEN=$(grep -i "authorization:" headers.txt | cut -d' ' -f2- | tr -d '\r\n')
curl -H "Authorization: $TOKEN" http://localhost:8081/api/v1/users/me
```

### 3. Frontend Testing

1. Navigate to `http://localhost:3000/login`
2. Login with test credentials
3. Verify redirect to dashboard
4. Check browser developer tools for JWT token in localStorage

## Troubleshooting

### Common Issues and Solutions

#### 1. "No verification key available" Error

**Problem**: JWT configuration not loaded properly.

**Solution**: 
- Ensure `JWT_SECRET_KEY` environment variable is set
- Restart Rails server after configuration changes
- Check that `devise-jwt` gem is properly installed

#### 2. CORS Errors

**Problem**: Frontend can't access API due to CORS restrictions.

**Solution**:
```ruby
# Ensure CORS is properly configured
# config/initializers/cors.rb
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins "http://localhost:3000" # Your frontend URL
    resource "*",
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head],
      credentials: true,
      expose: ['authorization'] # Critical!
  end
end
```

#### 3. Token Not Being Sent

**Problem**: Axios not sending Authorization header.

**Solution**:
- Check that token is stored correctly in localStorage
- Verify axios interceptor is configured
- Ensure `withCredentials: true` is set

#### 4. 401 Unauthorized on Protected Routes

**Problem**: Token validation failing.

**Solutions**:
- Check token format (should be "Bearer TOKEN")
- Verify JWT secret matches between generation and validation
- Check token expiration
- Ensure user exists in database

#### 5. Active Storage Configuration Errors

**Problem**: "Missing configuration for service" error.

**Solution**:
```ruby
# config/environments/development.rb
config.active_storage.service = :local

# config/storage.yml
local:
  service: Disk
  root: <%= Rails.root.join("storage") %>
```

## Best Practices

### Security Best Practices

1. **Environment Variables**: Never hardcode JWT secrets
```bash
# Use strong, unique secrets for each environment
JWT_SECRET_KEY=your_super_secure_secret_key_here
```

2. **Token Expiration**: Set reasonable expiration times
```ruby
jwt.expiration_time = 24.hours.to_i # Adjust based on your needs
```

3. **Token Revocation**: Implement proper logout
```ruby
# Ensure tokens are added to denylist on logout
jwt.revocation_requests = [
  ['DELETE', %r{^/users/sign_out$}]
]
```

4. **HTTPS in Production**: Always use HTTPS in production
```ruby
# config/environments/production.rb
config.force_ssl = true
```

### Development Best Practices

1. **Centralized Configuration**: Use single source of truth for API endpoints

2. **Error Handling**: Implement comprehensive error handling
```typescript
// Handle different error scenarios
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized
    } else if (error.response?.status >= 500) {
      // Handle server errors
    }
    return Promise.reject(error)
  }
)
```

3. **Loading States**: Show loading indicators during authentication

4. **Type Safety**: Use TypeScript interfaces for user data

### Production Considerations

1. **Environment Variables**: Use proper environment variable management
```bash
# Production environment variables
NEXT_PUBLIC_API_URL=https://api.yourdomain.com
JWT_SECRET_KEY=your_production_secret_key
```

2. **CORS Origins**: Restrict CORS to your production domains
```ruby
origins "https://yourdomain.com", "https://www.yourdomain.com"
```

3. **Token Storage**: Consider more secure storage options for sensitive applications
- HttpOnly cookies for maximum security
- Secure token refresh mechanisms

4. **Monitoring**: Add logging and monitoring for authentication events

## Example Project Structure

```
my_app_api/
├── app/
│   ├── controllers/
│   │   ├── application_controller.rb
│   │   ├── api/v1/
│   │   │   ├── base_controller.rb
│   │   │   └── users_controller.rb
│   │   └── users/
│   │       ├── sessions_controller.rb
│   │       └── registrations_controller.rb
│   ├── models/
│   │   ├── user.rb
│   │   └── jwt_denylist.rb
│   └── serializers/
├── config/
│   ├── initializers/
│   │   ├── devise.rb
│   │   └── cors.rb
│   ├── environments/
│   └── routes.rb
└── db/

my_app_frontend/
├── src/
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   └── login/
│   ├── components/
│   │   └── auth/
│   ├── hooks/
│   │   └── useAuth.tsx
│   └── lib/
│       ├── api.ts
│       └── config.ts
└── package.json
```

## Conclusion

This setup provides a robust, scalable authentication system that:

- ✅ **Secure**: Uses JWT with proper expiration and revocation
- ✅ **Scalable**: Centralized configuration for easy maintenance
- ✅ **Type-safe**: TypeScript interfaces for better development experience
- ✅ **Production-ready**: Proper error handling and security considerations
- ✅ **Maintainable**: Clean separation of concerns and single source of truth

The key to success is understanding that Devise JWT handles token generation and validation automatically when properly configured, while the frontend needs to properly extract and send tokens in the Authorization header.

### Additional Resources

- [Devise JWT Documentation](https://github.com/waiting-for-dev/devise-jwt)
- [Rails 8 API Documentation](https://guides.rubyonrails.org/api_app.html)
- [Next.js Authentication Patterns](https://nextjs.org/docs/authentication)
- [CORS Best Practices](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

---

**Author**: Based on real-world implementation experience  
**Last Updated**: September 2025  
**Rails Version**: 8.0.2+  
**Next.js Version**: 15.5.2+
