import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import PolicyRow from '../../../components/policy/PolicyRow';

describe('PolicyRow Component', () => {
  const mockProps = {
    policyId: 'TEST-POLICY-123',
    title: 'Test Policy',
    description: 'This is a test policy description',
    severity: 'High',
    enabled: true,
    onToggle: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders correctly with title and description', () => {
    render(<PolicyRow {...mockProps} />);
    // Title is only rendered as fallback if description is absent
    expect(screen.queryByText('Test Policy')).not.toBeInTheDocument();
    expect(screen.getByText('This is a test policy description')).toBeInTheDocument();
  });

  it('calls onToggle when the toggle button is clicked', () => {
    render(<PolicyRow {...mockProps} />);
    const toggles = document.querySelectorAll('.rounded-full.cursor-pointer');
    expect(toggles.length).toBeGreaterThan(0);
    fireEvent.click(toggles[0]);
    expect(mockProps.onToggle).toHaveBeenCalledTimes(1);
  });

  it('has the correct hover background color for UI consistency', () => {
    const { container } = render(<PolicyRow {...mockProps} />);
    // Verify that the row has the correct hover background class
    const row = container.querySelector('.hover\\:bg-\\[var\\(--elevated-surface\\)\\]');
    expect(row).toBeInTheDocument();
  });

  it('has the correct text colors for UI consistency', () => {
    const { container } = render(<PolicyRow {...mockProps} />);
    // Verify that the explicitly set text colors are present
    expect(container.querySelector('.text-\\[var\\(--muted\\)\\]')).toBeInTheDocument();
  });

  it('renders severity badge correctly', () => {
    render(<PolicyRow {...mockProps} />);
    expect(screen.getAllByText('High').length).toBeGreaterThan(0);
  });
});
