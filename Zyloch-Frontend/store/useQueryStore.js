import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export const useQueryStore = create(
  persist(
    (set) => ({
      queryHistory: [],
      savedQueries: [],
      currentQuery: '',
      currentVariables: '{}',
      
      setCurrentQuery: (query) => set({ currentQuery: query }),
      setCurrentVariables: (variables) => set({ currentVariables: variables }),
      
      addToHistory: (query, variables) =>
        set((state) => {
          const historyItem = {
            query,
            variables,
            timestamp: new Date().toISOString(),
            id: Date.now(),
          };
          return {
            queryHistory: [historyItem, ...state.queryHistory].slice(0, 20),
          };
        }),
      
      saveQuery: (name, query, variables) =>
        set((state) => ({
          savedQueries: [
            ...state.savedQueries,
            { id: Date.now(), name, query, variables },
          ],
        })),
      
      deleteSavedQuery: (id) =>
        set((state) => ({
          savedQueries: state.savedQueries.filter((q) => q.id !== id),
        })),
    }),
    {
      name: 'graphql-query-storage',
    }
  )
);
