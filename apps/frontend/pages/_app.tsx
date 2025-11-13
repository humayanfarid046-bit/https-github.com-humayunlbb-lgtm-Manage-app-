import '../styles/globals.css'
import type { AppProps } from 'next/app'
import { useEffect, useState } from 'react'

export default function App({ Component, pageProps }: AppProps) {
  const [theme, setTheme] = useState<'light'|'dark'>('light')

  useEffect(() => {
    const t = localStorage.getItem('theme') as 'light'|'dark' | null
    if (t) setTheme(t)
  }, [])

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('theme', theme)
  }, [theme])

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-50">
      <Component {...pageProps} setTheme={setTheme} theme={theme} />
    </div>
  )
}
