import React from 'react'
import Sbom from '../components/scan/sbom/Sbom'
// Correct import path for Sbom component
// If you get a module not found error, use the following import instead:
// import Sbom from '../components/scan/sbom/Sbom'
// Or, if your folder structure is different, use:
// import Sbom from '../components/scan/sbom/Sbom'

const page = () => {
  return (
    <div className="h-full">
      <Sbom/>
    </div>
  )
}

export default page