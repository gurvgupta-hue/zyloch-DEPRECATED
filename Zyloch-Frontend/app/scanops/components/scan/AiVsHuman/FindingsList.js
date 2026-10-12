import { useState } from "react";
import FindingCard from "./FindingCard";

const FindingsList = ({ findings }) => {
  const [openCards, setOpenCards] = useState({});

  const toggleCard = (index) => {
    setOpenCards(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  return (
    <div 
      className="bg-surface rounded-2xl shadow-2 p-6"
      style={{ border: '1px solid var(--border)' }}
    >
      <h3 className="text-lg font-semibold text-text mb-4">
        Detection Results
      </h3>

      <div className="space-y-3">
        {findings.map((finding, index) => (
          <FindingCard
            key={index}
            finding={finding}
            isOpen={openCards[index]}
            onToggle={() => toggleCard(index)}
          />
        ))}
      </div>
    </div>
  );
};

export default FindingsList;
