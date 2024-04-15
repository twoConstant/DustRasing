import { useEffect, useState } from 'react'
import logo from '../assets/mainlogo.png'
import login from '../assets/login.png'
import Cloud from './Cloud'
import { useNavigate } from 'react-router-dom'

const mainStyleClass = 'w-full h-screen bg-[#111111]'

const loginTitleClass = 'flex justify-center items-center text-[#ffffff] text-[60px] font-black translate-y-[12.5rem]'

const logoStyleClass = 'flex justify-center items-center opacity-0 translate-y-[2.5rem] scale-0'

const buttonStyleClass = 'flex justify-center opacity-0 cursor-pointer'

const Splash = () => {
	const [titleEffect, setTitleEffect] = useState(loginTitleClass)
	const [logoEffect, setLogoEffect] = useState(logoStyleClass)
	const [buttonEffect, setButtonEffect] = useState(buttonStyleClass)
	const navigate = useNavigate()

	useEffect(() => {
		const timer1 = setTimeout(() => {
			setTitleEffect(titleEffect.replace('translate-y-[12.5rem]', 'translate-y-0') + ' transition-all duration-1000')
		}, 1000)
		const timer2 = setTimeout(() => {
			setLogoEffect(
				logoEffect.replace('opacity-0 translate-y-[2.5rem] scale-0', 'opacity-100 translate-y-0 scale-100') +
					' transition-all duration-1000'
			)
			setButtonEffect(buttonEffect.replace('opacity-0', 'opacity-100') + ' transition-all duration-1000')
		}, 2000)
		return () => {
			clearTimeout(timer1)
			clearTimeout(timer2)
		}
	}, [])

	return (
		<div
			style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}
			className={mainStyleClass}
		>
			<div className={titleEffect}>
				{Cloud(20, 150)}
				<div style={{ zIndex: '2' }}>WITT</div>
			</div>
			<div className={logoEffect}>
				{Cloud(48, 250)}
				<img style={{ zIndex: '2' }} src={logo} />
			</div>
			<div className={buttonEffect}>
				<img
					onClick={() => {
						navigate('/auth')
					}}
					src={login}
				/>
			</div>
		</div>
	)
}

export default Splash
