import axios from 'axios'
import { useNavigate } from 'react-router-dom'
interface IAlarmProps {
	notificationId: number
	event: string
	senderId: number
	time: string
	senderImg: string
	senderName: string
}
const AlarmItem = ({ props }: { props: IAlarmProps }) => {
	const token = localStorage.getItem('token')
	const navigate = useNavigate()
	const handleCheckAlarm = () => {
		axios
			.put(
				`${import.meta.env.VITE_BASE_URL}/notices/${props.notificationId}`,
				{},
				{
					headers: { Authorization: `Bearer ${token}` },
				}
			)
			.then(() => {
				// 해당 유저의 캐릭터 페이지로
				navigate(`/invitor/${props.senderId}`)
			})
			.catch((error) => {
				console.error('Error: ', error)
			})
	}

	return (
		<div className="flex items-center hover:bg-stone-800" onClick={handleCheckAlarm}>
			<div>
				<img src={props.senderImg} alt="" className="rounded-full w-12 h-12 mx-4 my-4" />
			</div>
			{props.event === 'follow' ? (
				<div className="text-white flex">
					<div className="w-56">{`${props.senderName}님이 당신을 팔로우해요 `}</div>
					<div className="">{props.time.slice(5, 10)}</div>
				</div>
			) : (
				<div className="text-white flex">
					<div className="w-56">{`${props.senderName}님에게 콕 찔렸어요!`}</div>
					<div className="">{props.time.slice(5, 10)}</div>
				</div>
			)}
		</div>
	)
}

export default AlarmItem
