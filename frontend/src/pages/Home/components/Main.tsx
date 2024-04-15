import UserProfile from './UserProfile'
import ActionBar from './ActionBar'
import background from '../assets/background_main.gif'
import { useEffect, useState } from 'react'
import { userstate } from '../../../components/StateVariables'
import { Cookies } from 'react-cookie'
import { getToken, getUserData } from './API'

const mainStyleClass = 'z-10 w-full h-screen px-[14px] py-[22px] bg-[#111111]'

const noticeStyleClass = `
absolute z-20 
px-[30px] py-5 
text-xs text-center font-semibold text-[#ffffff] 
whitespace-pre-wrap opacity-0 bottom-1/2 
`

const Main = () => {
	const cookie = new Cookies()
	const newNotice = userstate((state) => state.newNotice)
	const setNewNotice = userstate((state) => state.setNewNotice)

	const characters = userstate((state) => state.characters)
	const setCharacter = userstate((state) => state.setCharacter)
	const mydata = userstate((state) => state.mydata)
	const levels = userstate((state) => state.levels)

	const [noticeEffect, setNoticeEffect] = useState(noticeStyleClass)
	const [userdata, setUserData] = useState(mydata)

	const getMyStatus = (state: string) => {
		setNewNotice(`현재 캐릭터의 레벨은 ${state}입니다.\n 물을 주어 캐릭터를 성장시키세요!`)
		setTimeout(() => {
			setNoticeEffect(
				noticeEffect.replace('opacity-0 bottom-1/2', 'opacity-100 bottom-2/3 transition-all duration-300 ease-out')
			)
		}, 200)
		setTimeout(() => {
			setNoticeEffect(
				noticeEffect.replace('opacity-100 bottom-2/3 transition-all duration-300 ease-out', 'opacity-0 bottom-1/2')
			)
		}, 1800)
	}

	const getData = async () => {
		if (cookie.get('refresh_token')) {
			getToken(cookie.get('refresh_token')!).then((value) => {
				localStorage.setItem('token', value.data)
				getUserData(value.data).then((result) => {
					localStorage.setItem('mydata', JSON.stringify(result.data))
					setUserData(result.data)
					setCharacter(~~(mydata.growthPoint / 10))
				})
			})
		}
	}

	useEffect(() => {
		getData()
		if (localStorage.getItem('mydata')) {
			setUserData(JSON.parse(localStorage.getItem('mydata')!))
			setCharacter(~~(mydata.growthPoint / 10))
		}
	}, [mydata.growthPoint, localStorage.getItem('mydata')])

	return (
		<>
			<img
				className="w-full h-full max-w-screen-sm max-h-full"
				style={{ position: 'absolute', opacity: '0.3' }}
				src={background}
			/>
			<div style={{ display: 'flex', justifyContent: 'center' }}>
				<div className={noticeEffect}>{newNotice}</div>
			</div>
			<div
				style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', alignItems: 'center' }}
				className={mainStyleClass}
			>
				{UserProfile(userdata)}
				<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
					<img
						style={{ filter: 'brightness(1.3)', cursor: 'pointer' }}
						src={~~(mydata.growthPoint / 10) < 8? characters[~~(mydata.growthPoint / 10)] : characters[7]}
						onClick={() => {
							getMyStatus(`${~~(mydata.growthPoint / 10) < 8? levels[~~(mydata.growthPoint / 10)] : levels[7]}`)
						}}
					/>
				</div>
				{ActionBar(userdata)}
			</div>
		</>
	)
}

export default Main
