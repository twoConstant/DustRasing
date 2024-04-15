import { useNavigate } from 'react-router-dom'
import { IMenu, IMenuFunc } from '../../components/interfaces'
import Header from '../../components/Header'
import { useEffect } from 'react'
import { Cookies } from 'react-cookie'
import { getToken, getUserData } from '../Home/components/API'

const Login = () => {
	const navigate = useNavigate()
	const menu: IMenu = { left: undefined, center: '로그인', right: undefined }
	const func: IMenuFunc = { left_func: () => navigate('/'), right_func: undefined }
	const cookie = new Cookies()
	let token = cookie.get('refresh_token')

	const getData = async () => {
		if (cookie.get('refresh_token')) {
			getToken(cookie.get('refresh_token')!).then((value) => {
				localStorage.setItem('token', value.data)
				getUserData(value.data).then((result) => {
					localStorage.setItem('mydata', JSON.stringify(result.data))
					navigate('/')
				})
			})
		}
	}

	useEffect(() => {
		// const url = 'http://localhost:8081/api/oauth2/authorization/kakao'
		const url = 'https://j10d103.p.ssafy.io/api/oauth2/authorization/kakao'
		location.href = url
		token = cookie.get('refresh_token')
		if (token != '') {
			getData()
		}
	}, [token])

	return (
		<div className=" max-w-screen-sm">
			<Header menu={menu} func={func} />
			<div className="pt-24"></div>
		</div>
	)
}

export default Login
