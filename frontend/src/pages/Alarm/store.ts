import { create } from 'zustand'

interface ISSEStore {
	lastEventId: string
	setLastEventId: (newLastEventId: string) => void
}

export const useSSEStore = create<ISSEStore>((set) => ({
	lastEventId: '0',
	setLastEventId: (newLastEventId) => set({ lastEventId: newLastEventId }),
}))
