import { useEffect } from 'react'
import { mainstate } from '../../components/StateVariables'
import Main from './components/Main'
import Splash from './components/Splash'
import { Cookies } from 'react-cookie'
import { getToken, getUserData } from './components/API'

const Home = () => {
	const cookie = new Cookies()
	const { isLogin, setIsLogin } = mainstate((state) => ({
		isLogin: state.isLogin,
		setIsLogin: state.setIsLogin,
	}))

	useEffect(() => {
		// 로컬 디버깅 전용
		if (localStorage.getItem('token')) {
			setIsLogin(true)
		}

		if (cookie.get('refresh_token')) {
			getToken(cookie.get('refresh_token')!)
				.then((value) => {
					if (value) {
						localStorage.setItem('token', value.data)
						getUserData(value.data).then((result) => {
							localStorage.setItem('mydata', JSON.stringify(result.data))
							setIsLogin(true)
						})
					} else {
						cookie.remove('refresh_token')
						localStorage.clear()
						setIsLogin(false)
					}
				})
				.catch(() => {
					cookie.remove('refresh_token')
					localStorage.clear()
					setIsLogin(false)
				})
		}
	}, [cookie.get('refresh_token')])

	return <div>{isLogin ? <Main /> : <Splash />}</div>
}

export default Home
