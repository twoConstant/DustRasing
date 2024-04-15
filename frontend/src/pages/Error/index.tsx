import { RiProhibitedLine } from 'react-icons/ri'
import { Link } from 'react-router-dom'

const Error = () => {
	return (
		<div className="text-white h-screen flex flex-col justify-center items-center gap-3">
			<h1 className="flex justify-center items-center">
				<RiProhibitedLine className="size-16" />
				<p className="text-5xl font-bold">404</p>
			</h1>
			<p className="text-lg">페이지를 찾을 수 없습니다 :(</p>
			<Link to="/" className="hover:text-whiteText hover:underline">
				돌아가기
			</Link>
		</div>
	)
}

export default Error
