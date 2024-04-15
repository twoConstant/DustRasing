import { instance } from "../../instance"

export const postKock = async ({ userId }: {userId: number}) => {
	return await instance
		.post(`/user/kock/${userId}`)
		.then((response) => response.data)
		.catch((e) => console.log(`[Error] ${e}`))
}