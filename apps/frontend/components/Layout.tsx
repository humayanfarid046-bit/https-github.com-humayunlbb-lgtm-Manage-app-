import Navbar from './Navbar'

export default function Layout({ children, setTheme, theme }: any) {
  return (
    <div>
      <Navbar setTheme={setTheme} theme={theme} />
      <main>{children}</main>
    </div>
  )
}
