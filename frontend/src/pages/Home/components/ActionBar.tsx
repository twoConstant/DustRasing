import { useNavigate } from 'react-router-dom'
import heart from '../assets/love.svg'
import sun from '../assets/sun.svg'
import water from '../assets/water.svg'
import { data } from '../../../components/StateVariables'
import { useEffect, useState } from 'react'
import { feedCharacter, getUserData } from './API'

const PlusEffectClass = `
absolute 
rounded-[10px] 
z-[1] 
w-[6.625rem] h-[6.25rem] 
opacity-20 
bg-gradient-to-br from-[#d4ced600] via-[#e5d3eb55] to-[#d4ced600] 
hover:opacity-100 
hover:cursor-pointer 
hover:brightness-[1.3] 
hover:transtion-opacity 
transition ease-in-out duration-500
`

const actionStyleClass = 'z-[5] w-full h-[6.25rem] flex justify-around text-[#ffffff]'

const tileStyleClass = `
w-[6.625rem] h-[6.25rem] 
rounded-[10px] 
border border-[#ffffff2e] 
bg-gradient-to-br from-[#D9D9D928] from-17% to-[#D9D9D919] to-85.5% 
shadow-[0_4px_34px_#00000026] 
backdrop-blur-[50px] 
backdrop-brightness-100 
hover:scale-110
transition
`

const actionbuttonStyleClass = 'text-white text-sm font-normal pt-1'

const popupStyleClass = `
absolute z-20 
w-[15.625rem] h-[9.375rem] 
p-5 rounded-[20px] 
bg-[#ffffff] 
translate-y-[200%] 
flex-column justify-center items-center 
text-[#ac0013] text-xs font-medium text-center 
shadow-[0px_0px_15px_3px_#F2FCFC] scale-0 
`

const popupButtonStyleClass = `
w-20 h-10 
mx-2.5 my-10 
rounded-[20px] 
flex justify-center items-center 
text-xs text-[#777777] cursor-pointer 
`

const ActionBar = (mydata: data) => {
	const navigate = useNavigate()

	const [popupEffect, setPopupEffect] = useState(popupStyleClass)
	const [parameter, setParameter] = useState(mydata)
	const [comment, setComment] = useState(
		<div>
			캐릭터에게 먹이를 주시겠습니까?
			<br />
			현재 보유한 물병 중 1개가 차감됩니다.
		</div>
	)

	const feedWater = async () => {
		const token = localStorage.getItem('token')
		feedCharacter(token!).then(() => {
			getUserData(token!).then((result) => {
				localStorage.setItem('mydata', JSON.stringify(result.data))
				setPopupEffect(popupEffect.replace('scale-100 transition-scale duration-500', 'scale-0'))
			})
		})
	}

	const popupBox = (
		<div className={popupEffect}>
			{comment}
			<div className="flex justify-around items-center">
				<div
					style={{ display: 'flex' }}
					className={popupButtonStyleClass + 'bg-[#1cd44d]'}
					onClick={() => {
						if (mydata.bottle > 0) {
							feedWater()
						} else {
							setComment(
								<div>
									캐릭터에게 줄 물병이 없습니다.
									<br />
									퀴즈를 풀어 물병을 획득한 후 시도해주세요.
								</div>
							)
							const timer = setTimeout(() => {
								setPopupEffect(popupEffect.replace('scale-100 transition-scale duration-500', 'scale-0'))
							}, 500)
							clearTimeout(timer)
						}
					}}
				>
					확인
				</div>
				<div
					style={{ display: 'flex' }}
					className={popupButtonStyleClass + 'bg-[#dddddd]'}
					onClick={() => {
						setPopupEffect(popupEffect.replace('scale-100 transition-scale duration-500', 'scale-0'))
					}}
				>
					취소
				</div>
			</div>
		</div>
	)

	useEffect(() => {
		if (localStorage.getItem('mydata')) {
			const local = JSON.parse(localStorage.getItem('mydata')!)
			setParameter(local)
		}
	}, [localStorage.getItem('mydata')])

	return (
		<>
			{popupBox}
			<div className={actionStyleClass}>
				<div>
					<div
						style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}
						className={tileStyleClass}
						onClick={() => {
							navigate('quiz')
						}}
					>
						<div className={PlusEffectClass}></div>
						<img src={heart} />
						<div className={actionbuttonStyleClass}>퀴즈 풀러 가기</div>
					</div>
				</div>
				<div>
					<div
						style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}
						className={tileStyleClass}
						onClick={() => {
							if (!popupEffect.includes(' transition-scale duration-500')) {
								setPopupEffect(popupEffect.replace(' transition-scale duration-500', ''))
							}
							setPopupEffect(popupEffect.replace('scale-0', 'scale-100 transition-scale duration-500'))
						}}
					>
						<div className={PlusEffectClass}></div>
						<img src={water} />
						<div className={actionbuttonStyleClass}>물 주기{`(${parameter.bottle})`}</div>
					</div>
				</div>
				<div>
					<div
						style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}
						className={tileStyleClass}
						onClick={() => {
							navigate('follow')
						}}
					>
						<div className={PlusEffectClass}></div>
						<img src={sun} />
						<div className={actionbuttonStyleClass}>이웃 조회하기</div>
					</div>
				</div>
			</div>
		</>
	)
}

export default ActionBar
