import { useNavigate } from 'react-router-dom'
import { data, userstate } from '../../../components/StateVariables'
import avatar from '../assets/avatar.gif'
import { ImSearch } from 'react-icons/im' // 유저 검색 아이콘
import AlarmBell from '../../Alarm/components/AlarmBell' // 알림 조회 아이콘

const UserProfile = (mydata: data) => {
	const navigate = useNavigate()

	const profileStyleClass =
		'flex justify-center items-center z-[5] w-full h-[4.125rem] bg-[#342C3D] text-[#ffffff] font-black rounded-[15px]'

	const userinfoStyleClass = 'flex-column items-center w-1/2 h-full py-[10px] text-[10px]'

	const levelStyleClass =
		'flex justify-center items-center mr-0.5 w-[2.625rem] h-3.5 rounded-[5px] text-[#ffffff] text-[8px] bg-[#6DBE70]'

	const totalgaugeStyleClass = 'absolute mt-[3px] rounded-[5px] bg-[#92DAEB]'

	const gaugeStyleClass = 'z-[1] absolute mt-[3px] rounded-[5px] bg-[#AEEB92]'

	const levels = userstate((state) => state.levels)

	return (
		<div className={profileStyleClass}>
			<img
				width={60}
				style={{ borderRadius: '1000px', aspectRatio: '1/1', margin: '0px 10px' }}
				src={mydata.profileImg ? mydata.profileImg : avatar}
			/>
			<div className={userinfoStyleClass}>
				<div style={{ minWidth: '100px', width: '100%' }} className="flex justify-around my-[5px]">
					<span className={levelStyleClass}>{`${~~(mydata.growthPoint / 10) < 8? levels[~~(mydata.growthPoint / 10)] : levels[7]}`}</span>
					{`${mydata.userName}`}님<span className="mx-[15px] text-[8px]">{`${mydata.rank}`}위</span>
				</div>
				<div className="my-[5px]">
					<div>
						<span
							style={{
								width: '44%',
								maxWidth: '320px',
								height: '12.5px',
								display: 'flex',
								justifyContent: 'center',
								alignItems: 'center',
							}}
							className={totalgaugeStyleClass}
						>
							<div style={{ zIndex: '5' }}>{(mydata.growthPoint % 10) * 10}%</div>
						</span>
						<span
							style={{
								width: `${44 * ((mydata.growthPoint % 10) / 10)}%`,
								maxWidth: `${320 * ((mydata.growthPoint % 10) / 10)}px`,
								height: '12.5px',
							}}
							className={gaugeStyleClass}
						></span>
					</div>
				</div>
			</div>
			<div
				className="cursor-pointer mx-[10px]"
				onClick={() => {
					navigate('/search')
				}}
			>
				<ImSearch size={20} className="font-light" color="#ffffff" />
			</div>
			<div className="mx-[10px]">
				<AlarmBell />
			</div>
		</div>
	)
}

export default UserProfile
