import axios from 'axios'

export const instance = axios.create({
	baseURL: import.meta.env.VITE_BASE_URL,
	withCredentials: true,
})

instance.interceptors.request.use(
	(config) => {
		config.headers['Content-Type'] = 'application/json'
		config.headers['Authorization'] = `Bearer ${
			localStorage.getItem('token') ? localStorage.getItem('token') : import.meta.env.VITE_DEV_USER_TOKEN
		}`

		return config
	},
	(error) => {
		return Promise.reject(error)
	}
)
