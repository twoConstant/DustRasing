export const enum RecentItemType {
	USER = 'USER',
	KEYWORD = 'KEYWORD',
}

export interface ISearchKeyword {
	id: number
	text: string
}

export interface ISearchUser {
	id: number
	profileImg: string | null
	userName: string
	level?: number
	growth_point?: number
	solved_cnt?: number
	followCnt: number
	duplicateFollower: string | null
}

export interface UserInfoProp {
	userInfo: ISearchUser
}

export interface SearchItemProp {
	type: RecentItemType
	userUpdate?: (type: RecentItemType, userInfo?: ISearchUser, keyword?: ISearchKeyword) => void
	keyword?: ISearchKeyword
	profileImg?: string
	userInfo?: ISearchUser
}

export interface RecentSearchProp {
	userUpdate: (type: RecentItemType, userInfo?: ISearchUser, keyword?: ISearchKeyword) => void
	recentKeywords: ISearchKeyword[]
	recentUsers: ISearchUser[]
	handleDelete: (type: RecentItemType, id: number) => void
}

export interface searchProp {
	input: string | undefined
	setInput: React.Dispatch<React.SetStateAction<string>>
	setIsFocused: React.Dispatch<React.SetStateAction<boolean>>
	handleInput: (event: React.ChangeEvent<HTMLInputElement>) => void
	handleEnter: (event: React.KeyboardEvent<HTMLInputElement>) => void
}

export interface SearchResultProp {
	input: string
	userUpdate: (type: RecentItemType, userInfo?: ISearchUser, keyword?: ISearchKeyword) => void
}
