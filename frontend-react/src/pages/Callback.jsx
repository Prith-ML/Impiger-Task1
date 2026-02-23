import { useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'

const BACKEND_URL = 'http://localhost:3000'

export default function Callback() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const code = searchParams.get('code')
  const error = searchParams.get('error')

  useEffect(() => {
    if (error) {
      localStorage.setItem('auth_error', searchParams.get('error_description') || error)
      navigate('/')
      return
    }
    if (code) {
      exchangeCode(code)
    } else {
      navigate('/')
    }
  }, [code, error, navigate, searchParams])

  async function exchangeCode(code) {
    try {
      const res = await fetch(`${BACKEND_URL}/api/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code,
          redirectUri: window.location.origin + '/callback'
        })
      })
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      localStorage.setItem('access_token', data.accessToken)
      localStorage.setItem('refresh_token', data.refreshToken)
      navigate('/dashboard')
    } catch (err) {
      localStorage.setItem('auth_error', err.message)
      navigate('/')
    }
  }

  return (
    <div className="card">
      <div className="spinner" />
      <p>Completing login...</p>
    </div>
  )
}
