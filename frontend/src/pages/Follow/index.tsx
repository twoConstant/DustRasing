import { Outlet } from 'react-router-dom'
import Header from '../../components/Header'
import { IMenu, IMenuFunc } from '../../components/interfaces'
import { icons } from '../../constants/header-icons'
import SlideTab from './components/SlideTab'
import { useRouter } from '../../hooks/useRouter'

const followTabInfo = [
	{ name: '팔로워', path: '/follow' },
	{
		name: '팔로잉',
		path: '/follow/following',
	},
]
const Follow = () => {
	const { routeTo } = useRouter()
	const menu: IMenu = { left: icons.BACK, center: '친구들', right: undefined }
	const func: IMenuFunc = { left_func: () => routeTo('/'), right_func: undefined }

	return (
		<div className="w-full">
			<Header menu={menu} func={func} />
			<div className="pt-14 text-white">
				<SlideTab tabInfo={followTabInfo} />
				<Outlet />
			</div>
		</div>
	)
}

export default Follow
