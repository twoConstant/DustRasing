import { QueryFunctionContext } from '@tanstack/react-query'
import { instance } from '../../instance'

export const getFollowingList = async ({ queryKey }: QueryFunctionContext) => {
	const [, userId] = queryKey
	return await instance
		.get(`/user/following/list/${userId}`)
		.then((response) => response.data.data.content)
		.catch((e) => console.log(e))
}

export const getFollowerList = async ({ queryKey }: QueryFunctionContext) => {
	const [, userId] = queryKey
	return await instance
		.get(`/user/follower/list/${userId}`)
		.then((response) => response.data.data.content)
		.catch((e) => console.log(e))
}

export const postFollow = async ({ fromId }: {fromId: number}) => {
	return await instance
		.post(`/user/follow/${fromId}`)
		.then((response) => response.data)
		.catch((e) => console.log(`[Error] ${e}`))
}

export const deleteFollow = async ({ fromId }: {fromId: number}) => {
	return await instance
		.delete(`/user/unfollow/${fromId}`)
		.then((response) => response.data)
		.catch((e) => console.log(`[Error] ${e}`))
}
