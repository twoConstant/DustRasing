import { useMemo } from 'react'
import { QueryFunctionContext, useInfiniteQuery } from '@tanstack/react-query'
import { instance } from '../../instance'
import { ISearchUser } from './search-types'

export const getSearchList = async ({
	queryKey,
	pageParam,
}: QueryFunctionContext<(number | string | boolean)[], number>) => {
	const [, userName] = queryKey
	const fetchSize = import.meta.env.VITE_PAGE_SIZE

	const response = await instance.get('/user/search', {
		params: {
			userName: userName,
			page: pageParam,
			size: fetchSize,
		},
	})

	return response.data.data.content
}

const useInfiniteSearch = (userName: string) => {
	const { data, isLoading, isError, hasNextPage, fetchNextPage, isFetchingNextPage } = useInfiniteQuery({
		queryKey: ['searchList', userName],
		queryFn: getSearchList,
		initialPageParam: 0,
		getNextPageParam: (lastPageInfo) => {
			return lastPageInfo ? (!lastPageInfo.last ? null : lastPageInfo.number + 1) : null
		},
	})

	const searchListData = useMemo(() => {
		const result: ISearchUser[] = []
		if (data) {
			data.pages.forEach((pageInfo) => {
				if (pageInfo) {
					pageInfo.forEach((newUser: ISearchUser) => {
						const hasUser = result.some((user) => user.id == newUser.id)

						if (!hasUser) {
							result.push(newUser)
						}
					})
				}
			})
		}
		return [...result]
	}, [data])

	return {
		searchListData,
		isLoading,
		isError,
		hasNextPage,
		fetchNextPage,
		isFetchingNextPage,
	}
}

export default useInfiniteSearch
