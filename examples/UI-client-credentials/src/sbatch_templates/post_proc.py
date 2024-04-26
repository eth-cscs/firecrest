#!/bin/bash
#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
# script provided by Jean M. Favre
# to be run with pvbatch, which is the batch-mode executable for ParaView:
# execute the next two lines:

# module load daint-gpu ParaView; srun -C gpu -N1 -n1 -t 00:05:00 -A csstaff -p debug pvbatch post_proc.py
# convert /scratch/snx3000/eirinik/results/imag.*png /scratch/snx3000/eirinik/imag.gif

from paraview.simple import *

import glob
import sys

workdir = sys.argv[1]
fnames = glob.glob(f"{workdir}/*.vtu")
fnames.sort()

renderView1 = GetRenderView()
renderView1.ViewSize = [800, 512]
renderView1.InteractionMode = '2D'
renderView1.AxesGrid = 'GridAxes3DActor'
renderView1.CenterOfRotation = [13.5, 0.0, 0.0]
renderView1.StereoType = 'Crystal Eyes'
renderView1.CameraPosition = [13.5, 0.0, 8000.0]
renderView1.CameraFocalPoint = [13.5, 0.0, 0.0]
renderView1.CameraFocalDisk = 1.0
renderView1.CameraParallelScale = 15

# init the 'GridAxes3DActor' selected for 'AxesGrid'
renderView1.AxesGrid.Visibility = 1

reader = XMLUnstructuredGridReader(FileName=fnames)
reader.PointArrayStatus = ['Velocity', 'Pressure']
reader.UpdatePipelineInformation()

nb_of_timesteps = len(reader.TimestepValues)
print("Found ", nb_of_timesteps, " timesteps: ", reader.TimestepValues)
renderView1.ViewTime = reader.TimestepValues[-1] # force reading of last timestep to initialize color properly


# create a new 'Contour'
contour1 = Contour(Input=reader)
contour1.ContourBy = ['POINTS', 'Pressure']
contour1.Isosurfaces = [0.8630544543266296, 0.16583216190338135, 0.32077044910854763, 0.4757087363137139, 0.6306470235188801, 0.7855853107240465, 0.9405235979292128, 1.095461885134379, 1.2504001723395453, 1.4053384595447116, 1.560276746749878]
contour1.UpdatePipeline()

rep0 = Show(reader, renderView1)
rep0.Representation = 'Surface'
ColorBy(rep0,('POINTS', 'Pressure'))

rep1 = Show(contour1, renderView1)
rep1.Representation = 'Surface'
ColorBy(rep1,('POINTS', 'Pressure'))

pressureLUT = GetColorTransferFunction('Pressure')
pressureLUT.RescaleTransferFunction(0.1, 1.6)

rep0.SetScalarBarVisibility(renderView1, True)

scalar_bar = GetScalarBar(pressureLUT, renderView1)
scalar_bar.ScalarBarLength = [0.98]
scalar_bar.LabelFormat = '%.1f'
scalar_bar.RangeLabelFormat = '%.1f'
scalar_bar.TitleJustification = 'Centered'
scalar_bar.AutoOrient = 0
scalar_bar.Orientation = 'Horizontal'

renderView1.OrientationAxesVisibility = 0

renderView1.CenterAxesVisibility = 0


for i, t in enumerate(reader.TimestepValues):
    GetActiveView().ViewTime = reader.TimestepValues[i]
    SaveScreenshot(f"{workdir}/imag.{t:04}.png")
