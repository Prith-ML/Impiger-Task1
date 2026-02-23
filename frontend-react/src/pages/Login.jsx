import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const BACKEND_URL = 'http://localhost:3000'
const REDIRECT_URI = window.location.origin + '/callback'

function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

export default function Login() {
  const navigate = useNavigate()
  const [authConfig, setAuthConfig] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (token) {
      navigate('/dashboard')
      return
    }
    loadConfig()
  }, [navigate])

  async function loadConfig() {
    try {
      const res = await fetch(`${BACKEND_URL}/api/auth/config`)
      const config = await res.json()
      setAuthConfig(config)
    } catch (err) {
      setError('Failed to load auth config')
    } finally {
      setLoading(false)
    }
  }

  function handleLogin() {
    if (!authConfig) return
    const state = generateRandomString(32)
    localStorage.setItem('oauth_state', state)
    const url = new URL(authConfig.authUrl)
    url.searchParams.append('client_id', authConfig.clientId)
    url.searchParams.append('redirect_uri', REDIRECT_URI)
    url.searchParams.append('response_type', 'code')
    url.searchParams.append('scope', 'openid profile email')
    url.searchParams.append('state', state)
    window.location.href = url.toString()
  }

  function handleRegister() {
    if (!authConfig) return
    const state = generateRandomString(32)
    localStorage.setItem('oauth_state', state)
    const url = new URL(authConfig.registerUrl)
    url.searchParams.append('client_id', authConfig.clientId)
    url.searchParams.append('redirect_uri', REDIRECT_URI)
    url.searchParams.append('response_type', 'code')
    url.searchParams.append('scope', 'openid profile email')
    url.searchParams.append('state', state)
    window.location.href = url.toString()
  }

  if (loading) return <div className="card"><div className="spinner" /></div>
  if (error) return <div className="card"><p className="error">{error}</p></div>

  return (
    <div className="card">
      <h1 style={{ marginBottom: '0.5rem' }}>Address Book</h1>
      <p style={{ color: '#718096', marginBottom: '1.5rem' }}>Login with Keycloak to manage contacts</p>
      <button className="btn btn-primary" onClick={handleLogin}>
        Login with Keycloak
      </button>
      <br />
      <button className="btn btn-primary" onClick={handleRegister} style={{ marginTop: '0.75rem', background: '#38a169' }}>
        Register New Account
      </button>
    </div>
  )
}
