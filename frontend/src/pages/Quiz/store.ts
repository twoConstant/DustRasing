import { create } from 'zustand'

interface IQuizStore {
	answerType: number
	image: File | null
	setAnswerType: (newAnswerType: number) => void
	setImage: (newImage: File) => void
}

export const useQuizStore = create<IQuizStore>((set) => ({
	answerType: 0,
	image: null,
	setAnswerType: (newAnswerType) => set({ answerType: newAnswerType }),
	setImage: (newImage) => set({ image: newImage }),
}))
