## @file
#  Platform description.
#
# Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
#
# This program and the accompanying materials are licensed and made available under
# the terms and conditions of the BSD License which accompanies this distribution.
# The full text of the license may be found at
# http://opensource.org/licenses/bsd-license.php
#
# THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#
##

################################################################################
#
# Defines Section - statements that will be processed to create a Makefile.
#
################################################################################
[Defines]
  PLATFORM_NAME                       = MinPlatformPkg
  PLATFORM_GUID                       = 8FE55D15-3ABF-4175-8169-74B87E5CD175
  PLATFORM_VERSION                    = 0.1
  DSC_SPECIFICATION                   = 0x00010005
  OUTPUT_DIRECTORY                    = Build/MinPlatformPkg
  SUPPORTED_ARCHITECTURES             = IA32|X64
  BUILD_TARGETS                       = DEBUG|RELEASE
  SKUID_IDENTIFIER                    = DEFAULT

################################################################################
#
# SKU Identification section - list of all SKU IDs supported by this
#                              Platform.
#
################################################################################
[SkuIds]
  0|DEFAULT              # The entry: 0|DEFAULT is reserved and always required.

################################################################################
#
# Pcd Section - list of all EDK II PCD Entries defined by this Platform
#
################################################################################
  
[PcdsFeatureFlag]
  # configuration
    gMinPlatformModuleTokenSpaceGuid.PcdBootToShellOnly|FALSE
    gMinPlatformModuleTokenSpaceGuid.PcdUefiSecureBootEnable|FALSE
    gMinPlatformModuleTokenSpaceGuid.PcdTpm2Enable|FALSE
    gMinPlatformModuleTokenSpaceGuid.PcdPerformanceEnable|FALSE

################################################################################
#
# Library Class section - list of all Library Classes needed by this Platform.
#
################################################################################

!include MinPlatformPkg/Include/Dsc/CoreCommonLib.dsc
!include MinPlatformPkg/Include/Dsc/CorePeiLib.dsc
!include MinPlatformPkg/Include/Dsc/CoreDxeLib.dsc

[LibraryClasses.common]
  #
  # Platform
  #
  PlatformHookLib|MdeModulePkg/Library/BasePlatformHookLibNull/BasePlatformHookLibNull.inf
  PciHostBridgeLib|MinPlatformPkg/Pci/Library/PciHostBridgeLibSimple/PciHostBridgeLibSimple.inf
  PciSegmentInfoLib|MinPlatformPkg/Pci/Library/PciSegmentInfoLibSimple/PciSegmentInfoLibSimple.inf
  PlatformBootManagerLib|MinPlatformPkg/Bds/Library/DxePlatformBootManagerLib/DxePlatformBootManagerLib.inf
  AslUpdateLib|MinPlatformPkg/Acpi/Library/DxeAslUpdateLib/DxeAslUpdateLib.inf
  
  #
  # Misc
  #
  FspWrapperApiLib|IntelFsp2WrapperPkg/Library/BaseFspWrapperApiLib/BaseFspWrapperApiLib.inf
  FspWrapperApiTestLib|IntelFsp2WrapperPkg/Library/PeiFspWrapperApiTestLib/PeiFspWrapperApiTestLib.inf
  FspWrapperHobProcessLib|MinPlatformPkg/FspWrapper/Library/PeiFspWrapperHobProcessLib/PeiFspWrapperHobProcessLib.inf
  PlatformSecLib|MinPlatformPkg/FspWrapper/Library/SecFspWrapperPlatformSecLib/SecFspWrapperPlatformSecLib.inf

  FspWrapperPlatformLib|MinPlatformPkg/FspWrapper/Library/PeiFspWrapperPlatformLib/PeiFspWrapperPlatformLib.inf

  BoardInitLib|MinPlatformPkg/PlatformInit/Library/BoardInitLibNull/BoardInitLibNull.inf
  BoardAcpiTableLib|MinPlatformPkg/Acpi/Library/BoardAcpiLibNull/BoardAcpiTableLibNull.inf
  BoardAcpiEnableLib|MinPlatformPkg/Acpi/Library/BoardAcpiLibNull/BoardAcpiEnableLibNull.inf
  SiliconPolicyInitLib|MinPlatformPkg/PlatformInit/Library/SiliconPolicyInitLibNull/SiliconPolicyInitLibNull.inf
  SiliconPolicyUpdateLib|MinPlatformPkg/PlatformInit/Library/SiliconPolicyUpdateLibNull/SiliconPolicyUpdateLibNull.inf

  TestPointCheckLib|MinPlatformPkg/Test/Library/TestPointCheckLibNull/TestPointCheckLibNull.inf
  
[LibraryClasses.common.SEC]
  TestPointCheckLib|MinPlatformPkg/Test/Library/TestPointCheckLib/SecTestPointCheckLib.inf

[LibraryClasses.common.PEIM]
  #
  # PEI phase common
  #
  FspWrapperPlatformLib|MinPlatformPkg/FspWrapper/Library/PeiFspWrapperPlatformLib/PeiFspWrapperPlatformLib.inf
  TestPointCheckLib|MinPlatformPkg/Test/Library/TestPointCheckLib/PeiTestPointCheckLib.inf
  TestPointLib|MinPlatformPkg/Test/Library/TestPointLib/PeiTestPointLib.inf

[LibraryClasses.common.DXE_DRIVER]
  #
  # DXE phase common
  #
  FspWrapperPlatformLib|MinPlatformPkg/FspWrapper/Library/DxeFspWrapperPlatformLib/DxeFspWrapperPlatformLib.inf
  TestPointCheckLib|MinPlatformPkg/Test/Library/TestPointCheckLib/DxeTestPointCheckLib.inf
  TestPointLib|MinPlatformPkg/Test/Library/TestPointLib/DxeTestPointLib.inf

[LibraryClasses.common.DXE_SMM_DRIVER]
  SpiFlashCommonLib|MinPlatformPkg/Flash/Library/SpiFlashCommonLibNull/SpiFlashCommonLibNull.inf
  TestPointCheckLib|MinPlatformPkg/Test/Library/TestPointCheckLib/SmmTestPointCheckLib.inf
  TestPointLib|MinPlatformPkg/Test/Library/TestPointLib/SmmTestPointLib.inf

###################################################################################################
#
# Components Section - list of the modules and components that will be processed by compilation
#                      tools and the EDK II tools to generate PE32/PE32+/Coff image files.
#
# Note: The EDK II DSC file is not used to specify how compiled binary images get placed
#       into firmware volume images. This section is just a list of modules to compile from
#       source into UEFI-compliant binaries.
#       It is the FDF file that contains information on combining binary files into firmware
#       volume images, whose concept is beyond UEFI and is described in PI specification.
#       Binary modules do not need to be listed in this section, as they should be
#       specified in the FDF file. For example: Shell binary (Shell_Full.efi), FAT binary (Fat.efi),
#       Logo (Logo.bmp), and etc.
#       There may also be modules listed in this section that are not required in the FDF file,
#       When a module listed here is excluded from FDF file, then UEFI-compliant binary will be
#       generated for it, but the binary will not be put into any firmware volume.
#
###################################################################################################

[Components]

  MinPlatformPkg/Library/PeiLib/PeiLib.inf
  MinPlatformPkg/Library/PeiHobVariableLibFce/PeiHobVariableLibFce.inf
  MinPlatformPkg/Library/PeiHobVariableLibFce/PeiHobVariableLibFceOptSize.inf

  MinPlatformPkg/Acpi/AcpiTables/AcpiPlatform.inf
  MinPlatformPkg/Acpi/AcpiSmm/AcpiSmm.inf
  MinPlatformPkg/Acpi/Library/DxeAslUpdateLib/DxeAslUpdateLib.inf
  MinPlatformPkg/Acpi/Library/BoardAcpiLibNull/BoardAcpiEnableLibNull.inf
  MinPlatformPkg/Acpi/Library/BoardAcpiLibNull/BoardAcpiTableLibNull.inf
  MinPlatformPkg/Acpi/Library/MultiBoardAcpiSupportLib/DxeMultiBoardAcpiSupportLib.inf
  MinPlatformPkg/Acpi/Library/MultiBoardAcpiSupportLib/SmmMultiBoardAcpiSupportLib.inf

  MinPlatformPkg/Bds/Library/DxePlatformBootManagerLib/DxePlatformBootManagerLib.inf

  MinPlatformPkg/Flash/SpiFvbService/SpiFvbServiceSmm.inf
  MinPlatformPkg/Flash/Library/SpiFlashCommonLibNull/SpiFlashCommonLibNull.inf

  MinPlatformPkg/FspWrapper/SaveMemoryConfig/SaveMemoryConfig.inf
  MinPlatformPkg/FspWrapper/Library/PeiFspWrapperHobProcessLib/PeiFspWrapperHobProcessLib.inf
  MinPlatformPkg/FspWrapper/Library/SecFspWrapperPlatformSecLib/SecFspWrapperPlatformSecLib.inf
  MinPlatformPkg/FspWrapper/Library/PeiFspWrapperPlatformLib/PeiFspWrapperPlatformLib.inf
  MinPlatformPkg/FspWrapper/Library/DxeFspWrapperPlatformLib/DxeFspWrapperPlatformLib.inf
  
  MinPlatformPkg/Hsti/HstiIbvPlatformDxe/HstiIbvPlatformDxe.inf

  MinPlatformPkg/Pci/Library/PciHostBridgeLibSimple/PciHostBridgeLibSimple.inf

  MinPlatformPkg/PlatformInit/PlatformInitPei/PlatformInitPreMem.inf
  MinPlatformPkg/PlatformInit/PlatformInitPei/PlatformInitPostMem.inf
  MinPlatformPkg/PlatformInit/PlatformInitDxe/PlatformInitDxe.inf
  MinPlatformPkg/PlatformInit/PlatformInitSmm/PlatformInitSmm.inf
  MinPlatformPkg/PlatformInit/Library/SecBoardInitLibNull/SecBoardInitLibNull.inf
  MinPlatformPkg/PlatformInit/Library/BoardInitLibNull/BoardInitLibNull.inf
  MinPlatformPkg/PlatformInit/Library/MultiBoardInitSupportLib/PeiMultiBoardInitSupportLib.inf
  MinPlatformPkg/PlatformInit/Library/MultiBoardInitSupportLib/DxeMultiBoardInitSupportLib.inf
  MinPlatformPkg/PlatformInit/SiliconPolicyPei/SiliconPolicyPeiPreMem.inf
  MinPlatformPkg/PlatformInit/SiliconPolicyPei/SiliconPolicyPeiPostMem.inf
  MinPlatformPkg/PlatformInit/SiliconPolicyDxe/SiliconPolicyDxe.inf
  MinPlatformPkg/PlatformInit/Library/SiliconPolicyInitLibNull/SiliconPolicyInitLibNull.inf
  MinPlatformPkg/PlatformInit/Library/SiliconPolicyUpdateLibNull/SiliconPolicyUpdateLibNull.inf

  MinPlatformPkg/Test/Library/TestPointCheckLibNull/TestPointCheckLibNull.inf
  MinPlatformPkg/Test/Library/TestPointCheckLib/SecTestPointCheckLib.inf
  MinPlatformPkg/Test/Library/TestPointCheckLib/PeiTestPointCheckLib.inf
  MinPlatformPkg/Test/Library/TestPointCheckLib/DxeTestPointCheckLib.inf
  MinPlatformPkg/Test/Library/TestPointLib/DxeTestPointLib.inf
  MinPlatformPkg/Test/Library/TestPointLib/PeiTestPointLib.inf
  MinPlatformPkg/Test/Library/TestPointLib/SmmTestPointLib.inf
  MinPlatformPkg/Test/TestPointDumpApp/TestPointDumpApp.inf

!if gMinPlatformModuleTokenSpaceGuid.PcdTpm2Enable == TRUE
  MinPlatformPkg/Tcg/Tcg2PlatformPei/Tcg2PlatformPei.inf
  MinPlatformPkg/Tcg/Tcg2PlatformDxe/Tcg2PlatformDxe.inf
!endif