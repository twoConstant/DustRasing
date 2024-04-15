import { create } from 'zustand'
import dust from '../pages/Home/assets/dust.png'
import bud from '../pages/Home/assets/bud.png'
import flower from '../pages/Home/assets/flower.png'
import tree from '../pages/Home/assets/tree.png'
import mountain from '../pages/Home/assets/mountain.png'
import earth from '../pages/Home/assets/earth.png'
import baobabtree from '../pages/Home/assets/baobab_tree.png'
import thelittleprince from '../pages/Home/assets/the_little_prince.png'

export interface data {
	id: number
	userName: string
	profileImg: string
	solvedCnt: number
	growthPoint: number
	rank: number
	bottle: number
}

export interface IMainState {
	isLogin: boolean
	token: string
	setToken: (result: string) => void
	setIsLogin: (result: boolean) => void
}

export interface IUserState {
	characters: string[]
	levels: string[]
	character: number
	mydata: data
	newNotice: string
	notices: JSON[]
	setCharacter: (result: number) => void
	setNotices: (result: JSON[]) => void
	setNewNotice: (result: string) => void
}

export const mainstate = create<IMainState>()((set) => ({
	isLogin: localStorage.getItem('token') ? true : false,
	token: localStorage.getItem('token') ? localStorage.getItem('token')! : '',
	setToken: (result: string) => set({ token: result }),
	setIsLogin: (result: boolean) => set({ isLogin: result }),
}))

export const userstate = create<IUserState>()((set) => ({
	characters: [dust, bud, flower, tree, mountain, earth, baobabtree, thelittleprince],
	levels: ['먼지', '새싹', '꽃', '나무', '산', '지구', '바오밥나무', '어린왕자'],
	character: 0,
	mydata: localStorage.getItem('mydata')
		? JSON.parse(localStorage.getItem('mydata')!)
		: { id: -1, userName: 'guest', bottle: 0, growthPoint: 0, solvedCnt: 0, rank: 0 },
	newNotice: '',
	notices: [],
	setMyData: (result: data) => set((state) => ({ mydata: { ...state.mydata, result } })),
	setCharacter: (result: number) => set({ character: result }),
	setNotices: (result: JSON[]) => result.map((value) => set((state) => ({ notices: [...state.notices, value] }))),
	setNewNotice: (result: string) => set({ newNotice: result }),
}))
