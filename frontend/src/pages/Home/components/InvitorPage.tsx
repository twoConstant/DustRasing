import UserProfile from './UserProfile'
import avatar from '../assets/avatar.gif'
import background from '../assets/background_main.gif'
import { useEffect, useState } from 'react'
import { userstate } from '../../../components/StateVariables'
import { useParams } from 'react-router'
import { kock, otherUserData } from './API'
import { useRouter } from '../../../hooks/useRouter'
import { icons } from '../../../constants/header-icons'
import { useMutation } from '@tanstack/react-query'
import { deleteFollow, postFollow } from '../../Follow/api'
import { postKock } from '../api'

const mainStyleClass = 'z-10 w-full h-screen px-[14px] py-[22px] bg-[#111111]'

const initValue = {
	id: -1,
	profileImg: avatar,
	userName: 'guest',
	bottle: 0,
	growthPoint: 0,
	solvedCnt: 0,
	rank: 0,
	follower: false,
	following: false,
}

// const followButtonStyleClass = `
// w-[80px] h-[60px]
// rounded-[10px]
// flex justify-center items-center
// text-[#ffffff] text-xs
// `

const InvitorPage = () => {
	const { goBack } = useRouter()
	const characters = userstate((state) => state.characters)
	const [userdata, setUserData] = useState(initValue)
	const [kockEffect, setKockEffect] = useState('brightness-[1.3] cursor-pointer')
	const [isFollow, setIsFollow] = useState<boolean>(userdata.following)
	const [isKock, setIsKock] = useState<boolean>(false)

 	const { userId } = useParams()

	const getInvitorData = async () => {
		const token = localStorage.getItem('token')!
		otherUserData(token, parseInt(userId!)).then((value) => {
			setUserData(value.data)
		})
	}

	const makekock = async () => {
		const token = localStorage.getItem('token')!
		kock(token, parseInt(userId!)).then((value) => {
			if (value) {
				setTimeout(() => {
					setKockEffect(kockEffect.replace('brightness-[1.3]', 'brightness-[1.7]'))
				}, 300)
				setTimeout(() => {
					setKockEffect(kockEffect.replace('brightness-[1.7]', 'brightness-[1.3]'))
				}, 800)
			}
		})
	}

	useEffect(() => {
		if (userId) {
			getInvitorData()
		}
	}, [userdata])

	
	const follow = useMutation({ mutationFn: postFollow })
	const unfollow = useMutation({ mutationFn: deleteFollow })
	const mutateKock = useMutation({ mutationFn: postKock })

	const handleFollow = () => {
		follow.mutate({ fromId: userdata.id })
		setIsFollow(!isFollow)
	}
	const handleUnfollow = () => {
		unfollow.mutate({ fromId: userdata.id })
		setIsFollow(!isFollow)
	}
	const handleKock = () => {
		mutateKock.mutate({ userId: userdata.id })
		if (mutateKock.isSuccess) {
			setIsKock(!isKock)
		}
	}

	return (
		<>
			<img
				className="w-full h-full max-w-screen-sm max-h-full"
				style={{ position: 'absolute', opacity: '0.3' }}
				src={background}
			/>
			<div className="fixed text-whiteText top-0 z-10 flex items-center justify-between w-full max-w-screen-sm h-14 px-5 bg-background">
				<div onClick={goBack}>{icons.BACK}</div>
				<div className="text-lg font-bold">{userdata.userName}</div>
				<div className="invisible">{icons.BACK}</div>
			</div>
			<div
				style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', alignItems: 'center' }}
				className={`${mainStyleClass} pt-16`}
			>
				{UserProfile(userdata)}
				<div
					style={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}
					onClick={() => {
						makekock()
					}}
				>
					<img className={kockEffect} src={~~(userdata.growthPoint / 10) < 8 ? characters[~~(userdata.growthPoint / 10)] : characters[7]} />
				</div>

				{/* <div className="flex w-[200px] h-[100px] justify-around">
					<div
						className={
							userdata.follower ? followButtonStyleClass + 'bg-[#eb42d1]' : followButtonStyleClass + 'bg-[#cc99c4]'
						}
					>
						{userdata.follower ? '팔로잉중' : '언팔로잉'}
					</div>
					<div
						className={
							userdata.following ? followButtonStyleClass + 'bg-[#28edd6]' : followButtonStyleClass + 'bg-[#97bfbb]'
						}
					>
						{userdata.following ? '팔로우중' : '언팔로우'}
					</div>
				</div> */}
				<div className="flex justify-around w-full text-GrayText z-20 py-6">
					{!isFollow ? (
						<button
							onClick={handleFollow}
							className="hover:bg-purple-900 w-2/5 transition-colors bg-purple-950 rounded-xl py-2 shrink-0"
						>
							팔로우
						</button>
					) : (
						<button
							onClick={handleUnfollow}
							className="hover:bg-slate-600 w-2/5 transition-colors bg-slate-700 rounded-xl py-2 shrink-0"
						>
							팔로잉
						</button>
					)}
					<div className="flex justify-center items-center text-grayText w-2/5 bg-slate-800 rounded-xl py-2 transition-colors hover:bg-slate-700">
						{!isKock ? (
							<button onClick={handleKock}>콕 찌르기 👉🏻</button>
						) : (
							<button className="text-slate-400">콕 찔렀습니다</button>
						)}
					</div>
				</div>
			</div>
		</>
	)
}

export default InvitorPage
