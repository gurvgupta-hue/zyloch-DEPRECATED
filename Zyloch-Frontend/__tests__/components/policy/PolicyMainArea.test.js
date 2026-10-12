import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import PolicyMainArea from '../../../components/policy/PolicyMainArea';

// Mock PolicyRow to simplify testing of the parent component
jest.mock('../../../components/policy/PolicyRow', () => {
  return function MockPolicyRow({ title, onToggle }) {
    return <div data-testid="policy-row" onClick={onToggle}>{title}</div>;
  };
});

describe('PolicyMainArea Component', () => {
  it('renders the header correctly', () => {
    render(<PolicyMainArea />);
    expect(screen.getByText('Security › Workflow')).toBeInTheDocument();
  });

  it('renders a list of policies', () => {
    render(<PolicyMainArea />);
    const policies = screen.getAllByTestId('policy-row');
    expect(policies.length).toBeGreaterThan(0);
  });

  it('contains overscroll-contain class on the list container to prevent scroll chaining', () => {
    const { container } = render(<PolicyMainArea />);
    // The list container has custom-scrollbar and we added overscroll-contain to fix page scrolling
    const listContainer = container.querySelector('.custom-scrollbar');
    expect(listContainer).toBeInTheDocument();
    expect(listContainer).toHaveClass('overscroll-contain');
  });

  it('has enable all and disable all buttons', () => {
    render(<PolicyMainArea />);
    expect(screen.getByText('Enable all')).toBeInTheDocument();
    expect(screen.getByText('Disable all')).toBeInTheDocument();
  });
});
