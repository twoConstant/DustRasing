import { Outlet } from 'react-router-dom'

const MainWrapper = () => {
	return (
		<div className="w-full max-w-screen-sm">
			<Outlet />
		</div>
	)
}

export default MainWrapper
