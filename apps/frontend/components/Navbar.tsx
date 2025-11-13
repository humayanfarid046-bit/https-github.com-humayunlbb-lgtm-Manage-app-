import Link from 'next/link'

export default function Navbar({ setTheme, theme }: any) {
  return (
    <header className="bg-white dark:bg-gray-800 shadow">
      <div className="container mx-auto p-4 flex justify-between items-center">
        <Link href="/" className="font-bold">College</Link>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            className="px-3 py-1 rounded bg-gray-100 dark:bg-gray-700"
          >
            {theme === 'dark' ? 'Light' : 'Dark'}
          </button>
          <Link href="/login" className="px-3 py-1 rounded bg-blue-600 text-white">Login</Link>
        </div>
      </div>
    </header>
  )
