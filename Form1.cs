using System.Data.Common;
using System.Diagnostics;
using System.Windows.Forms;

namespace Xpass
{
    public partial class Form1 : Form
    {
        private List<string> selectedFiles = [];
        public Form1()
        {
            InitializeComponent();
            ImproveDataGridView();
        }

        private void ImproveDataGridView()
        {

            // ���ø��н�����ɫ
            dataGridView1.RowsDefaultCellStyle.BackColor = Color.White;
            dataGridView1.AlternatingRowsDefaultCellStyle.BackColor = Color.LightGray;

            // �ٷֱ�
            double[] columnPercentages = [6, 25, 18, 8, 12, 20];
            int totalWidth = dataGridView1.Width - dataGridView1.RowHeadersWidth;
            // �����п�
            for (int i = 0; i < dataGridView1.Columns.Count; i++)
            {
                dataGridView1.Columns[i].HeaderCell.Style.WrapMode = DataGridViewTriState.False;
                if (i == dataGridView1.Columns.Count-1)
                {
                    dataGridView1.Columns[i].Width = totalWidth - 2 - (dataGridView1.Columns[0].Width + dataGridView1.Columns[1].Width + dataGridView1.Columns[2].Width + dataGridView1.Columns[3].Width + dataGridView1.Columns[4].Width);
                    break;
                }
                int newWidth = (int)(totalWidth * columnPercentages[i] / 100);
                dataGridView1.Columns[i].Width = newWidth;
            }
        }




        private void SelectFilesButton_Click(object sender, EventArgs e)
        {
            // ����û������ "ȷ��" ��ť
            if (openFileDialog1.ShowDialog(this) == DialogResult.OK)
            {

                if (openFileDialog1.FileNames.Length > 0)
                {
                    pathRichTextBox.Clear();
                    selectedFiles.Clear();
                    // ��ȡ�û�ѡ����ļ�·��
                    selectedFiles.AddRange(openFileDialog1.FileNames);

                    // �������ÿ��Ԫ��д�� RichTextBox��ÿ��Ԫ��ռ��һ��
                    foreach (string element in selectedFiles)
                    {
                        pathRichTextBox.AppendText(element + Environment.NewLine);
                    }
                }

            }
        }

        private void SelectDirButton_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog1.ShowDialog(this) == DialogResult.OK)
            {
                if (!string.IsNullOrEmpty(folderBrowserDialog1.SelectedPath))
                {
                    // ��� RichTextBox
                    pathRichTextBox.Clear();
                    selectedFiles.Clear();
                    pathRichTextBox.AppendText(folderBrowserDialog1.SelectedPath);
                    selectedFiles = Xclass.GetXshFiles(folderBrowserDialog1.SelectedPath);

                }
            }
        }

        private void AddRowToDataGridView(List<object> rowData)
        {
            // �����µ���
            DataGridViewRow row = new DataGridViewRow();

            // ���ÿһ�еĵ�Ԫ��
            for (int i = 0; i < rowData.Count; i++)
            {
                DataGridViewCell cell = new DataGridViewTextBoxCell();
                cell.Value = rowData[i];
                if (i == 5 && rowData[i] == "ȷ���������Ƿ���ȷ��")
                {
                    cell.Style.ForeColor = Color.Red;
                }

                row.Cells.Add(cell);
            }

            // ������ӵ�DataGridView
            dataGridView1.Rows.Add(row);
        }

        private void DecryptButton_Click(object sender, EventArgs e)
        {
            if (selectedFiles.Count > 0)
            {
                string sid;
                if (masterPasswdTextBox.Text.Length > 0)
                {
                    sid = masterPasswdTextBox.Text;
                }
                else
                {
                    sid = Xclass.GetSid();
                }
                dataGridView1.Rows.Clear();
                int index = 1;
                foreach (string element in selectedFiles)
                {
                    var session = Xclass.FileParser(element, sid);
                    var error = "ȷ���������Ƿ���ȷ��";
                    if (!session.isok)
                    {
                        session.password = error;
                    }

                    AddRowToDataGridView(new List<object> { index, element, session.host, session.port, session.userName, session.password });

                    index++;
                }
            }
            else if(pathRichTextBox.Text == "")
            {
                MessageBox.Show(this, "��ѡ���ļ�����Ŀ¼��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show(this, "δ�ҵ��Ự�ļ���", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Information);

            }
        }

        private void showPasswdCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (showPasswdCheckBox.Checked)
            {
                masterPasswdTextBox.PasswordChar = '\0';
            }
            else
            {
                masterPasswdTextBox.PasswordChar = '*';
            }
        }

    }
}
