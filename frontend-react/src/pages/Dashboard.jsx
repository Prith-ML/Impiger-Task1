import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const BACKEND_URL = 'http://localhost:3000'

export default function Dashboard() {
  const navigate = useNavigate()
  const [contacts, setContacts] = useState([])
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showForm, setShowForm] = useState(false)
  const [editingContact, setEditingContact] = useState(null)
  const [formData, setFormData] = useState({ name: '', email: '', phone: '', address: '' })

  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (!token) {
      navigate('/')
      return
    }
    loadData(token)
  }, [navigate])

  function getToken() {
    return localStorage.getItem('access_token')
  }

  async function loadData(token) {
    try {
      const [profileRes, contactsRes] = await Promise.all([
        fetch(`${BACKEND_URL}/api/user/profile`, {
          headers: { Authorization: `Bearer ${token}` }
        }),
        fetch(`${BACKEND_URL}/api/contacts`, {
          headers: { Authorization: `Bearer ${token}` }
        })
      ])

      if (profileRes.status === 401 || contactsRes.status === 401) {
        const refreshToken = localStorage.getItem('refresh_token')
        if (refreshToken) {
          const refreshRes = await fetch(`${BACKEND_URL}/api/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken })
          })
          const refreshData = await refreshRes.json()
          if (refreshData.accessToken) {
            localStorage.setItem('access_token', refreshData.accessToken)
            localStorage.setItem('refresh_token', refreshData.refreshToken)
            return loadData(refreshData.accessToken)
          }
        }
        localStorage.clear()
        navigate('/')
        return
      }

      const profile = await profileRes.json()
      const contactsData = await contactsRes.json()
      setUser(profile)
      setContacts(contactsData)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function openCreateForm() {
    setEditingContact(null)
    setFormData({ name: '', email: '', phone: '', address: '' })
    setShowForm(true)
  }

  function openEditForm(contact) {
    setEditingContact(contact)
    setFormData({
      name: contact.name,
      email: contact.email || '',
      phone: contact.phone || '',
      address: contact.address || ''
    })
    setShowForm(true)
  }

  function closeForm() {
    setShowForm(false)
    setEditingContact(null)
  }

  async function handleSubmit(e) {
    e.preventDefault()
    const token = getToken()
    if (!token) return

    try {
      if (editingContact) {
        const res = await fetch(`${BACKEND_URL}/api/contacts/${editingContact.id}`, {
          method: 'PUT',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(formData)
        })
        if (!res.ok) throw new Error('Update failed')
      } else {
        const res = await fetch(`${BACKEND_URL}/api/contacts`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(formData)
        })
        if (!res.ok) throw new Error('Create failed')
      }
      closeForm()
      loadData(token)
    } catch (err) {
      alert(err.message)
    }
  }

  async function handleDelete(id) {
    if (!confirm('Delete this contact?')) return
    const token = getToken()
    if (!token) return

    try {
      const res = await fetch(`${BACKEND_URL}/api/contacts/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      })
      if (!res.ok) throw new Error('Delete failed')
      loadData(token)
    } catch (err) {
      alert(err.message)
    }
  }

  async function handleLogout() {
    const token = localStorage.getItem('access_token')
    const refreshToken = localStorage.getItem('refresh_token')
    await fetch(`${BACKEND_URL}/api/auth/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ refreshToken })
    }).catch(() => {})
    localStorage.clear()
    try {
      const res = await fetch(`${BACKEND_URL}/api/auth/config`)
      const authConfig = await res.json()
      if (authConfig.logoutUrl) {
        window.location.href = `${authConfig.logoutUrl}?post_logout_redirect_uri=${encodeURIComponent(window.location.origin)}&client_id=${authConfig.clientId}`
        return
      }
    } catch (_) {}
    navigate('/')
  }

  if (loading) return <div className="card"><div className="spinner" /></div>
  if (error) return <div className="card"><p className="error">{error}</p></div>

  return (
    <div className="card card-wide">
      <div className="dashboard-header">
        <div>
          <h1>Welcome, {user?.name || user?.username}!</h1>
          <p className="user-email">{user?.email}</p>
        </div>
        <button className="btn btn-primary" onClick={openCreateForm}>
          + Add Contact
        </button>
      </div>

      <h2 className="section-title">Address Book</h2>
      {contacts.length === 0 ? (
        <p className="empty-state">No contacts yet. Click "Add Contact" to create one.</p>
      ) : (
        <ul className="contacts-list">
          {contacts.map((contact) => (
            <li key={contact.id} className="contact-card">
              <div className="contact-info">
                <h3>{contact.name}</h3>
                {contact.email && <p><span className="label">Email:</span> {contact.email}</p>}
                {contact.phone && <p><span className="label">Phone:</span> {contact.phone}</p>}
                {contact.address && <p><span className="label">Address:</span> {contact.address}</p>}
              </div>
              <div className="contact-actions">
                <button className="btn btn-small btn-edit" onClick={() => openEditForm(contact)}>Edit</button>
                <button className="btn btn-small btn-danger" onClick={() => handleDelete(contact.id)}>Delete</button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {showForm && (
        <div className="modal-overlay" onClick={closeForm}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <h2>{editingContact ? 'Edit Contact' : 'Add Contact'}</h2>
            <form onSubmit={handleSubmit}>
              <input
                type="text"
                placeholder="Name *"
                value={formData.name}
                onChange={e => setFormData({ ...formData, name: e.target.value })}
                required
              />
              <input
                type="email"
                placeholder="Email"
                value={formData.email}
                onChange={e => setFormData({ ...formData, email: e.target.value })}
              />
              <input
                type="tel"
                placeholder="Phone"
                value={formData.phone}
                onChange={e => setFormData({ ...formData, phone: e.target.value })}
              />
              <input
                type="text"
                placeholder="Address"
                value={formData.address}
                onChange={e => setFormData({ ...formData, address: e.target.value })}
              />
              <div className="form-actions">
                <button type="button" className="btn btn-secondary" onClick={closeForm}>Cancel</button>
                <button type="submit" className="btn btn-primary">{editingContact ? 'Update' : 'Create'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      <button className="btn btn-danger btn-logout" onClick={handleLogout}>
        Logout
      </button>
    </div>
  )
}
