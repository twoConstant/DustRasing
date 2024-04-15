import { createBrowserRouter } from 'react-router-dom'
import Home from './pages/Home'
import Login from './pages/Login'
import Quiz from './pages/Quiz'
import Follow from './pages/Follow'
import MainWrapper from './components/MainWrapper'
import Error from './pages/Error'
import FollowerTab from './pages/Follow/FollowerTab'
import FollowingTab from './pages/Follow/FollowingTab'
import Search from './pages/Search'
import AlarmPage from './pages/Alarm'
import CorrectPage from './pages/Quiz/Correct'
import WrongPage from './pages/Quiz/Wrong'
import InvitorPage from './pages/Home/components/InvitorPage'

const router = createBrowserRouter([
	{
		path: 'auth',
		element: <Login />,
	},
	{
		path: '/',
		element: <MainWrapper />,
		errorElement: <Error />,
		children: [
			{
				path: '/',
				element: <Home />,
			},
			{
				path: 'invitor/:userId',
				element: <InvitorPage />,
			},
			{
				path: 'follow',
				element: <Follow />,
				children: [
					{
						path: '',
						element: <FollowerTab />,
					},
					{
						path: 'following',
						element: <FollowingTab />,
					},
				],
			},
			{
				path: 'quiz',
				element: <Quiz />,
			},
			{
				path: 'quiz/correct',
				element: <CorrectPage />,
			},
			{
				path: 'quiz/wrong',
				element: <WrongPage />,
			},
			{
				path: 'search',
				element: <Search />,
			},
			{
				path: 'alarm',
				element: <AlarmPage />,
			},
		],
	},
])

export default router
