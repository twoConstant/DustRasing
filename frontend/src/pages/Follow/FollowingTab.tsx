import { useQuery } from '@tanstack/react-query'
import { getFollowingList } from './api'
import FollowUser from './components/FollowUser'
import { IFollowUser } from './FollowerTab'
import { useEffect, useState } from 'react'

const FollowingTab = () => {
	const userInfo = localStorage.getItem('mydata')
	const [userId, setUserId] = useState<number | null>(null)
	
	useEffect(() => {
		if (userInfo) {
			const userData = JSON.parse(userInfo)
			setUserId(userData.id)
		}
	})
	
	const { data: following } = useQuery<IFollowUser[]>({
		queryKey: ['following', userId],
		queryFn: getFollowingList,
		enabled: !!userId,
	})

	return (
		<div className="pt-12 px-5">
			<ul className="flex flex-col">
				{following &&
					following.map((user) => (
						<li key={user.id} className="flex text-textWthi justify-between items-center gap-4 my-2">
							<FollowUser user={user} />
						</li>
					))}
			</ul>
		</div>
	)
}

export default FollowingTab
